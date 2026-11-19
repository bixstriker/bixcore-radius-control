# Third-party dependencies and licenses

BiXCore's own source code is made available under the MIT License (see [LICENSE](LICENSE)).
Third-party packages remain subject to **their own** copyright notices and licenses.
The MIT License for BiXCore does not supersede them.

The following dependency closure was inspected on 19 November 2026 for
`fastapi==0.128.2`, `uvicorn==0.48.0`, and `httpx==0.28.1`
using the installed Python distribution metadata. The exact transitive versions
may change if you perform a fresh installation, because the requirements
pin direct dependencies only.

| Package | Inspected version | Reported license |
|---|---|---|
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.14.2 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| click | 8.5.0 | BSD-3-Clause |
| fastapi | 0.128.2 | MIT |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| idna | 3.19 | BSD-3-Clause |
| pydantic | 2.14.3 | MIT |
| pydantic_core | 2.50.4 | MIT |
| starlette | 0.50.0 | BSD-3-Clause |
| typing-inspection | 0.4.5 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| uvicorn | 0.48.0 | BSD-3-Clause |

**Distribution requirements:** Keep each third-party package's own license
text and applicable notices when redistributing binaries or vendored files.
In particular, `certifi` carries MPL-2.0 terms (including source and
modification obligations for MPL-covered material); do not remove
its notices. This project does not vendor Python packages. Docker
images include system and language-runtime components with their
separate licenses; inspect the specific image before redistributing it.

Authoritative package license and copyright notices are distributed
inside the installed wheels/distributions (often as `LICENSE`,
`LICENSE.txt`, or files in `*.dist-info/licenses/`).
This table is an inventory, **not** a substitute for those legal notices
or a full legal audit of all optional extras and operating-system packages.

License references:
- [MIT](https://opensource.org/license/mit)
- [BSD-3-Clause](https://opensource.org/license/bsd-3-clause)
- [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/)
- [Python Software Foundation License](https://docs.python.org/3/license.html)

Run an up-to-date SBOM/license scan before shipping a third-party Docker image.
