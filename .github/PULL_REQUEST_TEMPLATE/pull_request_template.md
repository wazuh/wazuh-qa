|Related issue|
|---|
||

<!--
This template reflects sections that must be included in new Pull requests.
Contributions from the community are really appreciated. If this is the case, please add the
"contribution" to properly track the Pull Request.

Please fill the table above. Feel free to extend it at your convenience.
-->

## Description

<!--
Add a clear description of how the problem has been solved.
-->

## Configuration options

<!--
When proceed, this section should include new configuration parameters.
-->

## Logs example

<!--
Paste here related logs and alerts
-->

## Tests

- [ ] Proven that tests **pass** when they have to pass.
- [ ] Proven that tests **fail** when they have to fail.
<!--
Important: Don't remove these checks if your PR modifies Python code.
-->
- [ ] Python codebase satisfies PEP-8 style style guide. `pycodestyle --max-line-length=120 --show-source --show-pep8 file.py`
- [ ] Python codebase is documented following the Google Style for Python docstrings.
- [ ] The test is documented in wazuh-qa/docs