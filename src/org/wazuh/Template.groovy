
package org.wazuh;
@Grab('org.yaml:snakeyaml:1.17')
import org.yaml.snakeyaml.Yaml

class Template{
  // Manage variables
  private String template_path;

  // Common variables
  private String id;
  private String description;
  private String version;
  private String creation_date;
  private String modification_date;
  private String provisioner;
  private String tier;
  private String category;
  private String[] tags;
  private String subcategory
  private String target;
  private boolean cluster_mode;
  private String[] cluster_target;
  private String[] os_groups;
  private String[] os_target;
  private int total_agents;
  private int total_managers;
  private String max_version_manager;
  private String min_version_manager;
  private boolean need_api;

  // Test variables
  private Map managers;
  private Map agents;

  Map data;


  Template(template_path = ''){
    this.template_path = template_path
    if(this.template_path != ''){
      loadTemplate(this.template_path)
    }
  }



  void loadTemplate(path = ''){
    Yaml parser = new Yaml()
    Map data = parser.load((path as File).text)
    this.data = data
  }



  void toString(){
    String result;

    result += 'ID: ' + id + '\n';
    result += 'Description: ' + description + '\n';
    result += 'Version: ' + version + '\n';
    result += 'Creation date: ' + creation_date + '\n';
    result += 'Modification date: ' + modification_date + '\n';
    result += 'Provisioner: ' + provisioner + '\n';
    result += 'Tier: ' + tier + '\n';
    result += 'Category: ' + category + '\n';
    result += 'Tags: ' + tags.toString() + '\n';
    result += 'Subcategory: ' + subcategory + '\n';
    result += 'Target: ' + target + '\n';
    result += 'Cluster mode: ' + cluster_mode + '\n';
    result += 'Cluster target: ' + cluster_target.toString() + '\n';
    result += 'OS groups: ' + os_groups.toString() + '\n';
    result += 'OS target: ' + os_target.toString() + '\n';
    result += 'Total agents: ' + toString(total_agents) + '\n';
    result += 'Total managers: ' + toString(total_managers) + '\n';
    result += 'Max manager version: ' + max_version_manager + '\n';
    result += 'Min manager version: ' + min_version_manager + '\n';
    result += 'Need API: ' + need_api + '\n';

    return result;
  }

















}
