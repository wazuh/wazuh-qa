#!groovy
@Grab('org.yaml:snakeyaml:1.17')
import org.yaml.snakeyaml.Yaml

Yaml parser = new Yaml()
Map data = parser.load(("./quality/tests/fim/specification.yml" as File).text)

boolean all_targets = false
boolean manager_target = false
boolean agent_target = false

def id = data.id
println("id: " + id)
def description = data.description
println("description: " + description)
def version = data.version
println("version: " + version)
def creation_date = data.creation_date
println("creation_date: " + creation_date)
def modification_date = data.modification_date
println("modification_date: " + modification_date)
def provisioner = data.provisioner
println("provisioner: " + provisioner)
def tier = data.tier
println("tier: " + tier)
def category = data.category
println("category: " + category)
def tags = data.tags
println("tags: " + tags)
def subcategory = data.subcategory
println("subcategory: " + subcategory)
def target = data.target
println("target: " + target)
def cluster_mode = data.cluster_mode
println("cluster_mode: " + cluster_mode)
def cluster_target = data.cluster_target
println("cluster_target: " + cluster_target)
def os_groups = data.os_groups
println("os_groups: " + os_groups)
def os_target = data.os_target
println("os_target: " + os_target)
def total_agents = data.total_agents
println("total_agents: " + total_agents)
def total_managers = data.total_managers
println("total_managers: " + total_managers)
def wazuh_max_version_manager = data.wazuh_max_version_manager
println("wazuh_max_version_manager: " + wazuh_max_version_manager)
def wazuh_min_version_manager = data.wazuh_min_version_manager
println("wazuh_min_version_manager: " + wazuh_min_version_manager)
def need_api = data.need_api
println("need_api: " + need_api)

def managers = data.managers
def agents = data.agents

// Target operations
if (target.matches("agent")){
    agent_target = true
} else if (target.matches("manager")){
    manager_target = true
} else if (target.matches("all")){
    all_targets = true
}
