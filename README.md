python-signify
==============

This is a Python implementation of OpenBSD's
[signify](https://man.openbsd.org/signify.1) utility. Currently it only
supports verifying detached signatures because this is the use case that I
needed from signify. However, since this is just a little bit of sugar on top
of the [ed25519](https://github.com/warner/python-ed25519) library, it will
be pretty trivial to support the other features that signify has.

More
----
- [tedu@'s post on signify](https://www.tedunangst.com/flak/post/signify)
- [BSDCan 2015 presentation about signify](https://www.openbsd.org/papers/bsdcan-signify.html)

License
-------
`python-signify` is licensed under the Apache 2.0 License.

```
Copyright 2017 John "LuaMilkshake" Marion

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
