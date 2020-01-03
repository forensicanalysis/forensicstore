# Copyright (c) 2019 Siemens AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Author(s): Jonas Plum

import argparse
import json
import sys

import forensicstore

def main():
    root_parser = argparse.ArgumentParser(description='Handle forensicstores')
    root_subparsers = root_parser.add_subparsers(dest='root_command')
    root_subparsers.required = True
    parser = root_subparsers.add_parser("item")

    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True

    create_parser = subparsers.add_parser("create")
    create_parser.add_argument('store')

    get_parser = subparsers.add_parser("get")
    get_parser.add_argument('id')
    get_parser.add_argument('store')

    select_parser = subparsers.add_parser("select")
    select_parser.add_argument('type')
    select_parser.add_argument('store')

    all_parser = subparsers.add_parser("all")
    all_parser.add_argument('store')

    insert_parser = subparsers.add_parser("insert")
    insert_parser.add_argument('json')
    insert_parser.add_argument('store')

    update_parser = subparsers.add_parser("update")
    update_parser.add_argument('id')
    update_parser.add_argument('json')
    update_parser.add_argument('store')

    import_parser = subparsers.add_parser("import")
    import_parser.add_argument('url')
    import_parser.add_argument('store')

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument('store')
    validate_parser.add_argument('--no-fail', action='store_true', dest="nofail")

    args = root_parser.parse_args()

    if args.command == "create":
        store = forensicstore.connect(args.store)
        store.close()
    elif args.command == "get":
        store = forensicstore.connect(args.store)
        item = store.get(args.id)
        print(json.dumps(item))
        store.close()
    elif args.command == "select":
        store = forensicstore.connect(args.store)
        items = list(store.select(args.type))
        print(json.dumps(items))
        store.close()
    elif args.command == "all":
        store = forensicstore.connect(args.store)
        items = list(store.all())
        print(json.dumps(items))
        store.close()
    elif args.command == "insert":
        store = forensicstore.connect(args.store)
        item = store.insert(json.loads(args.json))
        print(json.dumps(item))
        store.close()
    elif args.command == "update":
        store = forensicstore.connect(args.store)
        print(args.json)
        item = store.update(args.id, json.loads(args.json))
        print(json.dumps(item))
        store.close()
    elif args.command == "import":
        store = forensicstore.connect(args.store)
        store.import_forensicstore(args.url)
        store.close()
    elif args.command == "validate":
        store = forensicstore.connect(args.store)
        errors = store.validate()
        if errors:
            print(json.dumps(errors))
        if args.nofail:
            sys.exit(0)
        sys.exit(len(errors))
    else:
        NotImplementedError("Command %s does not exist" % args.command)


if __name__ == '__main__':
    main()
