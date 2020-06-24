Hello team,

`<YOUR_INTRODUCTION_TEXT>`

Closes #`<YOUR_ISSUE_NUMBER>`

# Tests logic

`<YOUR_LOGIC_TEST_DESCRIPTION>`

# Tests checks

- [ ] Proven that tests **pass** when they have to pass
- [ ] Proven that tests **fail** when they have to fail
- [ ] Proven that tests have the expected behavior in **RPM and DEB**
- [ ] Checked that **all vulnerability detector tests work correctly** (my changes don't break anything)
- [ ] Tested and passed in Jenkins. Build URL: `<YOUR_JENKINS_BUILD_URL>`
<!--
Important: Don't remove this check if your PR modifies Python code.
-->
- [ ] Python codebase satisfies PEP-8 style style guide. `pycodestyle --max-line-length=120 --show-source --show-pep8 file.py`

## RPM manager

- When the expected behavior occurs:

```
<PYTEST_RESULT>
```

- When the module fails because of `<YOUR_CAUSE>`:

```
<PYTEST_RESULT>
```

## DEB manager

- When the expected behavior occurs:

```
<PYTEST_RESULT>
```

- When the module fails because of `<YOUR_CAUSE>`:

```
<PYTEST_RESULT>
```

## Integrity check with other tests


```
<PYTEST_RESULT>
```

Best regards.
