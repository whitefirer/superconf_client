# coding=utf-8
import json
import os
import shutil
from kazoo.client import KazooClient
from loguru import logger as default_logger

default_mask_rules = [
    {
        'regex_pattern': '(\".*?{key_word}[^\\s]*\"\\s*:\\s*")(.*?)(\")',
        'sub': '\\1********\\3',
        'key_words': ['password', 'passwd', 'secret', 'token', 'key'],
        'description': '对形如<code>"{key_word}": "{mask_value}"</code>的敏感数据进行脱敏',
    },
    {
        'regex_pattern': '({key_word}://)([^\\s]*?)(@)',
        'sub': '\\1********\\3',
        'key_words': ['redis', 'mongo', 'mysql', 'postgres', 'http', 'https'],
        'description': '对形如<code>{key_word}://{mask_value}@host:port</code>的敏感数据进行脱敏',
    }
]


def mask_value(data, mask_rules=[]):
    if mask_rules == []:
        mask_rules = default_mask_rules

    import re
    for rule in mask_rules:
        key_words = rule.get('key_words', [])
        for key_word in key_words:
            p = re.compile(rule['regex_pattern'].format(
                key_word=key_word), re.DOTALL | re.IGNORECASE)
            data = p.sub(rule['sub'], data)

    return bytes(data, 'utf8')


class ZKClient(KazooClient):
    def __init__(self, timeout=10.0, handler=None, *args, **kwargs):
        super(ZKClient, self).__init__(
            timeout=timeout, handler=handler, *args, **kwargs)
        if handler:
            event = self.start_async()

            # Wait for 30 seconds and see if we're connected
            event.wait(timeout=30)

            if not self.connected:
                # Not connected, stop trying to connect
                self.stop()
                raise Exception("Unable to connect.")
        else:
            self.start(timeout)

    def __del__(self):
        self.stop()


class SuperconfClient:
    def __init__(self, zk_client, logger=None):
        self.zk = zk_client
        if not logger:
            logger = default_logger
        self.logger = logger

    def __del__(self):
        self.zk.stop()
        del self.zk

    def get(self, path):
        return self.zk.get(path=path)

    def get_nodes(self, path):
        return self.zk.get_children(path=path)

    def exists_node(self, path):
        return self.zk.exists(path=path)

    def create_node(self, path, acl, data=b'', encode='utf8', makepath=True):
        if type(data) != bytes:
            data = bytes(data, encode)

        if self.zk.exists(path=path):
            return None
        return self.zk.create(path=path, value=data, acl=acl, makepath=makepath)

    def delete_node(self, path, recursive=True):
        return self.zk.delete(path=path, recursive=recursive)

    def set(self, path, data, encode='utf8'):
        if type(data) != bytes:
            data = bytes(data, encode)
        return self.zk.set(path=path, value=data)

    def walk(self, path, result=[], callback=None, exclude=['/zookeeper']):
        if not callback:
            callback = self.echo

        data, stat = self.zk.get(path=path)
        children = self.zk.get_children(path=path)
        acl, acl_stat = self.zk.get_acls(path=path)

        callback(
            path=path,
            data=data,
            stat=stat,
            children=children,
            acl=acl,
            acl_stat=acl_stat
        )

        if len(children) <= 0:
            return

        for sub in children:
            if path in exclude:
                continue
            sub_path = ''
            if path != '/':
                sub_path = path + '/' + sub
            else:
                sub_path = '/' + sub

            self.walk(sub_path, result, callback, exclude)

    def diff_view(self, tree, diff_data={}, mask=True, config=dict(diff_code=True)):
        node_map = {}
        diff_code = config.get('diff_code')

        # f'[yellow]{src_path}[/yellow]->[green]{dst_path}'
        parent_diff_path = ''

        node_style = dict(
            inte_children=dict(
                color='white',
                mark_flag='',
            ),
            add_children=dict(
                color='green',
                mark_flag='+++++',
            ),
            remove_children=dict(
                color='red',
                mark_flag='-----',
            )
        )

        src_data = diff_data.get("src_data")
        dst_data = diff_data.get("dst_data")

        if diff_code and src_data != dst_data:

            from rich.table import Table
            from rich.syntax import Syntax

            src_syntax = Syntax(
                src_data, "json", line_numbers=True, code_width=60)
            dst_syntax = Syntax(
                dst_data, "json", line_numbers=True, code_width=60)

            table = Table()
            table.add_column(diff_data.get("src_path"), max_width=60)
            table.add_column(diff_data.get("dst_path"), max_width=60)
            table.add_row(src_syntax, dst_syntax)
            tree.add(table)

        for child_type in ['inte_children', 'add_children', 'remove_children']:
            for child in diff_data[child_type]:
                node = f"[{node_style[child_type]['color']}]{node_style[child_type]['mark_flag']} {child} {parent_diff_path}"
                node_map[child] = tree.add(node)

        return node_map

    def diff(self, src_path, dst_path, result=[], exclude=['/zookeeper'], inherit=True, view=True, tree=None, mask=True):
        try:
            src_data, src_data_stat = self.zk.get(path=src_path)
            src_children = self.zk.get_children(path=src_path)
        except Exception as e:
            self.logger.debug(str(e))
            src_path = ''
            src_data = bytes('', 'utf-8')
            src_children = []

        try:
            dst_data, dst_data_stat = self.zk.get(path=dst_path)
            dst_children = self.zk.get_children(path=dst_path)
        except Exception as e:
            self.logger.debug(str(e))
            dst_data = bytes('', 'utf-8')
            dst_children = []

        diff_data = dict(
            src_path=src_path,
            dst_path=dst_path,
            src_data=str(mask_value(str(src_data, 'utf-8')), 'utf-8'),
            dst_data=str(mask_value(str(dst_data, 'utf-8')), 'utf-8'),
            src_children=src_children,
            dst_children=dst_children,
            inte_children=list(
                set(src_children).intersection(set(dst_children))),
            union_children=list(set(src_children).union(set(dst_children))),
            remove_children=list(
                set(dst_children).difference(set(src_children))),
            add_children=list(set(src_children).difference(set(dst_children))),
        )

        view_ret = {}

        if view:
            if tree == None:
                from rich.tree import Tree
                tree = Tree(f"[yellow]{src_path}[/yellow]->[green]{dst_path}")

            view_ret.update(self.diff_view(tree, diff_data))

        if src_data != dst_data or diff_data.get("add_children") or diff_data.get("remove_children"):
            result.append(diff_data)

        print(src_data, dst_data)

        if not inherit:
            return result, tree

        if len(src_children) <= 0:
            return result, tree

        for sub in src_children:
            if src_path in exclude:
                continue
            src_sub_path = ''
            if src_path != '/':
                src_sub_path = src_path + '/' + sub
            else:
                src_sub_path = '/' + sub

            dst_sub_path = ''
            if dst_path != '/':
                dst_sub_path = dst_path + '/' + sub
            else:
                dst_sub_path = '/' + sub

            sub_tree = view_ret.get(sub)

            self.diff(src_sub_path, dst_sub_path, result,
                      exclude, inherit, view, sub_tree)

        return result, tree

    def copy(self, transaction, src_path, dst_path, acl_path='', exclude=['/zookeeper'], inherit=True):
        if acl_path == '':
            acl_path = src_path

        acl, acl_stat = self.zk.get_acls(acl_path)

        data, data_stat = self.zk.get(path=src_path)
        children = self.zk.get_children(path=src_path)

        try:
            if self.exists_node(path=dst_path):
                transaction.set_data(path=dst_path, value=data)
            else:
                transaction.create(path=dst_path, value=data, acl=acl)
        except Exception as e:
            print(str(e))

        if not inherit:
            return

        if len(children) <= 0:
            return

        for sub in children:
            if src_path in exclude:
                continue
            src_sub_path = ''
            if src_path != '/':
                src_sub_path = src_path + '/' + sub
            else:
                src_sub_path = '/' + sub

            dst_sub_path = ''
            if dst_path != '/':
                dst_sub_path = dst_path + '/' + sub
            else:
                dst_sub_path = '/' + sub

            self.copy(transaction, src_sub_path, dst_sub_path,
                      acl_path=acl_path, exclude=exclude)

    def export(self, path, export_dir="", exclude=['/zookeeper']):
        data, stat = self.zk.get(path=path)
        children = self.zk.get_children(path=path)
        acl, acl_stat = self.zk.get_acls(path=path)

        self.export_save(
            export_dir,
            path=path,
            data=data,
            stat=stat,
            children=children,
            acl=acl,
            acl_stat=acl_stat
        )

        if len(children) <= 0:
            return

        for sub in children:
            if path in exclude:
                continue
            sub_path = ''
            if path != '/':
                sub_path = path + '/' + sub
            else:
                sub_path = '/' + sub

            self.export(sub_path, export_dir, exclude)

    def echo(self, **kwargs):
        for item in kwargs:
            print(item, kwargs[item])

    def export_save(self, export_dir, **kwargs):
        path = kwargs['path']
        sava_path = f'{export_dir}{path}'

        print('export', path, 'to', 'save_path')

        is_exists = os.path.exists(sava_path)

        if not is_exists:
            os.makedirs(sava_path)

        for item in kwargs:
            if item == 'acl':
                tmp_acls = []
                for i in kwargs[item]:
                    tmp_acls.append(dict(
                        id=dict(
                            scheme=i.id.scheme,
                            id=i.id.id
                        ),
                        perms=i.perms,
                        acl_list=i.acl_list
                    ))

                with open(f'{sava_path}/acl.json', 'w') as fp:
                    fp.write(json.dumps(tmp_acls))
            elif item == 'acl_stat':
                tmp_acl_stat = dict(
                    czxid=kwargs[item].czxid,
                    mzxid=kwargs[item].mzxid,
                    ctime=kwargs[item].ctime,
                    mtime=kwargs[item].mtime,
                    version=kwargs[item].version,
                    cversion=kwargs[item].cversion,
                    aversion=kwargs[item].aversion,
                    ephemeralOwner=kwargs[item].ephemeralOwner,
                    dataLength=kwargs[item].dataLength,
                    numChildren=kwargs[item].numChildren,
                    pzxid=kwargs[item].pzxid,
                )
                with open(f'{sava_path}/acl_stat.json', 'w') as fp:
                    fp.write(json.dumps(tmp_acl_stat))
            elif item == 'stat':
                temp_stat = dict(
                    czxid=kwargs[item].czxid,
                    mzxid=kwargs[item].mzxid,
                    ctime=kwargs[item].ctime,
                    mtime=kwargs[item].mtime,
                    version=kwargs[item].version,
                    cversion=kwargs[item].cversion,
                    aversion=kwargs[item].aversion,
                    ephemeralOwner=kwargs[item].ephemeralOwner,
                    dataLength=kwargs[item].dataLength,
                    numChildren=kwargs[item].numChildren,
                    pzxid=kwargs[item].pzxid,
                )
                with open(f'{sava_path}/stat.json', 'w') as fp:
                    fp.write(json.dumps(temp_stat))
            elif item == 'children':
                with open(f'{sava_path}/children.json', 'w') as fp:
                    fp.write(json.dumps(kwargs[item]))
            elif item == 'data':
                with open(f'{sava_path}/data.json', 'w') as fp:
                    fp.write(str(kwargs[item], 'utf8'))
            else:
                pass

    def backup(self, zk_path, backup_dir, exclude=['/zookeeper'], rm_tmp=True):
        from datetime import datetime
        import tarfile
        import time
        start_time = time.time()
        time_str = datetime.now().strftime('%Y%m%d%H%M%S')
        backup_name = f"zkbk_{time_str}"
        backup_path = f'{backup_dir}/{backup_name}'

        self.export(zk_path, backup_path, exclude=exclude)
        backup_fullpath = f'{backup_dir}/{backup_name}.tar.gz'
        with tarfile.open(backup_fullpath, 'w:gz') as tar:
            print('start tar backupfile')
            tar.add(backup_path, '/')

        end_time = time.time()
        cost_time = end_time - start_time

        if rm_tmp:
            shutil.rmtree(backup_path)
        print(f'The backup file is {backup_fullpath}, cost {cost_time}s')

        return backup_fullpath

    def restore(self, backup_file, zk_path):
        import tarfile
        import time
        from datetime import datetime
        start_time = time.time()

        print('start resotre')
        time_str = datetime.now().strftime('%Y%m%d%H%M%S')
        backup_name = f"zkre_{time_str}"
        extract_path = f'/tmp/{backup_name}'

        with tarfile.open(backup_file) as tar:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner) 
                
            
            safe_extract(tar, extract_path)
            for tarinfo in tar:
                if tarinfo.isdir():
                    print(tarinfo.name, "is", tarinfo.size,
                          "bytes in size and is a directory")
                    dst_path = f'{zk_path}/{tarinfo.name}'
                    print(f'restore to {dst_path}')
                    ephemeral = False
                    try:
                        with open(f'{extract_path}/{tarinfo.name}/stat.json', 'r') as fp:
                            stat = json.loads(fp.read())
                            if stat['ephemeralOwner'] != 0:
                                ephemeral = True
                    except Exception as e:
                        print(str(e))
                        continue

                    try:
                        with open(f'{extract_path}/{tarinfo.name}/data.json', 'r') as fp:
                            data = bytes(fp.read(), 'utf8')

                    except Exception as e:
                        print(str(e))

                    try:
                        with open(f'{extract_path}/{tarinfo.name}/acl.json', 'r') as fp:
                            raw_acl = json.loads(fp.read())
                            acl = []

                            from kazoo.security import make_acl
                            for i in raw_acl:
                                acl_dict = {}
                                for perm in i['acl_list']:
                                    if perm == 'ALL':
                                        acl_dict['all'] = True
                                    if perm == 'READ':
                                        acl_dict['read'] = True
                                    if perm == 'WRITE':
                                        acl_dict['write'] = True
                                    if perm == 'CREATE':
                                        acl_dict['create'] = True
                                    if perm == 'DELETE':
                                        acl_dict['delete'] = True
                                    if perm == 'ADMIN':
                                        acl_dict['admin'] = True

                                    acl.append(
                                        make_acl(i['id']['scheme'], i['id']['id'], **acl_dict))
                    except Exception as e:
                        print(str(e))

                    if self.exists_node(path=dst_path):
                        self.set(path=dst_path, data=data)
                    else:
                        self.create_node(path=dst_path, acl=acl, data=data)

        shutil.rmtree(extract_path)
        end_time = time.time()
        cost_time = end_time - start_time
        print(f'restore cost {cost_time}s')


if __name__ == "__main__":
    from kazoo.handlers.gevent import SequentialGeventHandler
    client = SuperconfClient(
        zk_client=ZKClient(
            timeout=3600,
            handler=SequentialGeventHandler(),
            hosts='****',
            auth_data=[('digest', '****:********')]
        )
    )

    backupfile_path = client.backup('/superconf', '/tmp')
    client.restore(backupfile_path, '/superconf_backup')
