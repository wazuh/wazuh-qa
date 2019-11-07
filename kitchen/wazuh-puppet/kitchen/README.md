**KITCHEN-PUPPET TESTING**


**1.Building Kitchen Directory Structure**
```
├── chefignore
├── Gemfile
├── hieradata
├── kitchen.yml
├── manifests
├── modules `should contain wazuh-puppet module`
├── Puppetfile
├── run.sh
├── test
```

Find more details in the [official documentation](https://kitchen.ci/)

**2. Required Gems**

Kitchen basically works with `Ruby` gems and so, all required packages are available as gems. In our case, we would need the following gems to be installed. Found in the file `Gemfile` :

```
vagrant@master:~/wazuh-puppet/kitchen$ cat Gemfile
# frozen_string_literal: true
source "https://rubygems.org"

# gem "rails"
gem "test-kitchen"
gem "kitchen-puppet"
gem "kitchen-vagrant"
gem 'kitchen-docker', '~> 2.3'
gem "puppet"
gem "librarian-puppet"
```

As we can see, we have gems for docker, vagrant, puppet, and kitchen itself.

Once we have our list of gems prepared, we install them running the following command:

```
bundle install
```

**3. Adding Dependencies**

A step which is already applied here is the creation of `Puppetfile` using `puppet-librerian` by running the command:

```
± librarian-puppet init
      create  Puppetfile
```

As you can see the, `Puppetfile` already exist with the following content:

```
#!/usr/bin/env ruby
#^syntax detection

forge "https://forgeapi.puppetlabs.com"

# use dependencies defined in metadata.json
#metadata

mod "wazuh/wazuh"
# use dependencies defined in Modulefile
# modulefile

# A module from the Puppet Forge
# mod 'puppetlabs-stdlib'

# A module from git
# mod 'puppetlabs-ntp',
#   :git => 'git://github.com/puppetlabs/puppetlabs-ntp.git'

# A module from a git branch/tag
# mod 'puppetlabs-apt',
#   :git => 'https://github.com/puppetlabs/puppetlabs-apt.git',
#   :ref => '1.4.x'

# A module from Github pre-packaged tarball
# mod 'puppetlabs-apache', '0.6.0', :github_tarball => 'puppetlabs/puppetlabs-apache'
```

Once `Puppetfile` is prepared, then we run need to get the requested module, by running:

 ```
 librarian-puppet install
 ```
 

**4. Kitchen Environment Configuration**

In the file `kitchen.yml` we have to configure the machines were our tests will be running. This configuration includes information, such as : 
* The virtualization tool `vagrant` or `docker`, 
* The operating system image, 
* Testing suites `testinfra` for example, etc ...

- An initial example of `kitchen.yml` would be:

```
vagrant@master:~/wazuh-puppet/kitchen$ cat kitchen.yml
---
driver:
  name: docker

provisioner:
  name: puppet_apply
  manifests_path: manifests
  modules_path: modules
  hiera_data_path: hieradata

platforms:
  - name: ubuntu-manager_00
    run_options: --ip 10.1.0.19
    driver_config:
      image: ubuntu:14.04
      platform: ubuntu
      hostname: manager00_ubuntu

  - name: ubuntu-agent
    driver_config:
      image: ubuntu:14.04
      platform: ubuntu
      hostname: agent00_ubuntu

suites:
  - name: default
    manifest: site.pp
    verifier:
      name: shell
      command: py.test -v test/base
```

**5. Put Kitchen in action** 

Once we have `kitchen.yml` prepared, then we can create the environment by running:

```
kitchen create
```

This way we will only have our machines created without installing the desired components to be tested. These components are represented by Wazuh stack components such as `wazuh-manager`, `wazuh-agent`, etc ...

**5. Install the required components to be tested then**

In `Puppet` case, to specify the `manifests` to be installed, we should configure the file 'manifests/site.pp', which by now it looks like:

```
node 'manager00_ubuntu' {
  class { "wazuh::manager":
        configure_wodle_openscap => false
  }
}
node 'agent00_ubuntu' {
  class { "wazuh::agent":
        ossec_ip => "manager_ip",
        configure_wodle_openscap => false
  }
}
```

As you can see, we only want to install `wazuh-manager` and `wazuh-agent`.


**6. Kitchen Converging: Installing the packages to be tested**

Once `site.pp` is prepared, we run:
```
kitchen converge
```

**7. Testing**

`Kitchen` offers a large variety of testing types, such as:
* Bats tests.
* Serverspec tests.
* Testinfra tests.
* <Maybe there are more ' to be discovered later' >

In our case, we think that `testinfra` is the best choice based on old experience. so and in order to implemente `testinfra` tests, we should indicate the testing suite command in `kitchen.yml` as indicated before:
```
suites:
  - name: default
    manifest: site.pp
    verifier:
      name: shell
      command: py.test -v test/base
```

In the folder test/base, we put our tests. By now we implemented 2 tests, one for `wazuh-manager` and another one for `wazuh-agent`. Please check both here: 
* [manager](https://github.com/wazuh/wazuh-puppet/blob/v3.9.5_7.2.1/kitchen/test/base/test_wazuh_manager.py)
* [agent](https://github.com/wazuh/wazuh-puppet/blob/v3.9.5_7.2.1/kitchen/test/base/test_wazuh_agent.py)

Once we have our suite prepared, then we run:

```
kitchen verify
```

And in a successful testing attempt we can get something like:

```
-----> Starting Kitchen (v2.2.5)
-----> Verifying <default-ubuntu-manager-00>...
       [Shell] Verify on instance default-ubuntu-manager-00  ...

============================= test session starts ==============================
platform linux -- Python 3.4.3, pytest-4.6.4, py-1.8.0, pluggy-0.12.0 -- /usr/bin/python3.4
cachedir: .pytest_cache
rootdir: /home/vagrant/wazuh-puppet/kitchen
plugins: testinfra-3.0.5
collecting ... collected 8 items

test/base/test_wazuh_agent.py::test_wazuh_agent_package SKIPPED          [ 12%]
test/base/test_wazuh_agent.py::test_wazuh_processes_running[ossec-agentd-ossec] SKIPPED [ 25%]
test/base/test_wazuh_agent.py::test_wazuh_processes_running[ossec-execd-root] SKIPPED [ 37%]
test/base/test_wazuh_agent.py::test_wazuh_processes_running[ossec-syscheckd-root] SKIPPED [ 50%]
test/base/test_wazuh_agent.py::test_wazuh_processes_running[wazuh-modulesd-root] SKIPPED [ 62%]
test/base/test_wazuh_manager.py::test_wazuh_agent_package PASSED         [ 75%]
test/base/test_wazuh_manager.py::test_wazuh_packages_are_installed PASSED [ 87%]
test/base/test_wazuh_manager.py::test_wazuh_services_are_running PASSED  [100%]

===================== 3 passed, 5 skipped in 1.18 seconds ======================
       Finished verifying <default-ubuntu-manager-00> (0m2.16s).
-----> Kitchen is finished. (0m4.51s)
```
