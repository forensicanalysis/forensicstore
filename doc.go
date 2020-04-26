// Copyright (c) 2019 Siemens AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Author(s): Jonas Plum

// Package forensicstore can create,
// access and process forensic artifacts bundled in so called forensicstores
// (a database for metadata and subfolders with forensic artifacts).
//
// The forensicstore format
//
// The forensicstore format implements the following conventions:
//     - The forensicstore is a folder containing an item.db file and an arbitrary number of other folders.
//     - The item.db file contains metadata for all extracted artifacts in a forensic investigation in jsonlite format (flattened json objects in a sqlite database).
//     - Items are represented as json objects.
//     - Items are valid STIX 2.0 Observable Objects where applicable.
//     - Items must not have dots (".") in their json keys.
//     - Files stored in the forensicstore are referenced by item attributes ending in _path, e.g. export_path, stdout_path and wmi_path.
//     - Any item stored in the forensicstore can have an errors attribute that contains errors that are related to retrieval or processing of this item.
//
// Structure
//
// An example directory structure for a forensicstore:
//     example.forensicstore/
//     ├── ChromeCache
//     │   ├── 0003357376fd75df_0
//     │   └── ...
//     ├── ChromeHistory
//     │   └── History
//     ├── ...
//     └── item.db
package forensicstore
