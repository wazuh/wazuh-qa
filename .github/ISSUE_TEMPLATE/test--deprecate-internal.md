---
name: 'Test: Internal options deprecation'
about: Test suite for internal options deprecation.
title: ''
labels: ''
assignees: ''

---

# Internal options deprecation

| Version | Revision |
| --- | --- |
| x.y.z | rev |

## Summary
- [ ] INT001
- [ ] INT002
- [ ] INT003
- [ ] INT004
- [ ] INT005
- [ ] INT006

## INT001

**Short description**

Default values

**Category**

Internal options deprecation

**Subcategory**

Options values

**Description**

The default values will be set if no options (old internal options) are specified neither in `ossec.conf` nor in `internal_options.conf`/`local_internal_options.conf`.
These values are specified in the Wazuh documentation.

**Configuration sample**

Default configuration (no options set). Non-existent or empty `internal_options.conf` and `local_internal_options.conf`.

**Min/Max compatible versions**
3.12.0 - Current

## INT002

**Short description**

Read options in `ossec.conf`

**Category**

Internal options deprecation

**Subcategory**

Options values

**Description**

The old internal options can be read in `ossec.conf`
These new options are specified in the Wazuh documentation.

**Configuration sample**

Non-existent or empty `internal_options.conf` and `local_internal_options.conf`.
The following options are the adaptation of the old internal options in `ossec.conf`. Please add them in the existing block if needed. Be careful to configure every option where it belongs (`client` module only in the agent, for example).
Also, remember to active all needed modules (like `mail`, `cluster` or `integrator`).

``` xml
### CLIENT ###
<client>
    <state_interval>5</state_interval>                  
    <recv_timeout>60</recv_timeout>                     
    <remote_conf>1</remote_conf>                        
    <!-- This option sets Windows' debug in a Windows agent and Agentd's debug in any other agent -->
    <log_level>0</log_level>
    <max_attempts>4</max_attempts>                      
    <request>  
      <rto_sec>1</rto_sec>                              
      <rto_msec>0</rto_msec>                            
      <pool>10</pool>                                   
    </request>
    <recv_counter_flush>128</recv_counter_flush>        
    <comp_avg_printout>19999</comp_avg_printout>        
    <verify_msg_id>0</verify_msg_id>                    
    <thread_stack_size>8192</thread_stack_size>         
  <client>

  <client_buffer>
    <tolerance>18</tolerance>                           
    <bucket>
      <warn_level>92</warn_level>                       
      <normal_level>73</normal_level>                   
    </bucket>
    <min_eps>48</min_eps>                               
  </client_buffer>
 
  ### REMOTE ###
  <remote>
    <recv_counter_flush>77</recv_counter_flush>         
    <comp_avg_printout>17589</comp_avg_printout>        
    <verify_msg_id>1</verify_msg_id>                    
    <pass_empty_keyfile>1</pass_empty_keyfile>          
    <rlimit_nofile>58963</rlimit_nofile>                
    <log_level>2</log_level>                                
    <pool>      
      <sender>9</sender>                                
      <request>777</request>                            
      <worker>7</worker>                                
    </pool>     
    <timeout>     
      <max_attempts>7</max_attempts>                    
      <request>8</request>                              
      <response>51</response>                           
      <recv>2</recv>                                    
      <send>3</send>                                    
    </timeout>      
    <request>     
      <rto_sec>5</rto_sec>                               
      <rto_msec>12</rto_msec>                            
    </request>      
    <shared>      
      <merge>0</merge>    
      <reload>9</reload>                               
    </shared>     
    <interval>      
      <state>4</state>     
      <keyupdate>6</keyupdate>    
    </interval>     
    <group>     
      <guess_agent>1</guess_agent>   
      <data_flush>77777</data_flush>         
    </group>      
    <memory>      
      <receive_chunk>3956</receive_chunk>
      <buffer_relax>2</buffer_relax>                
    </memory>     
    <tcp>     
      <keepidle>156</keepidle>       
      <keepintvl>95</keepintvl>          
      <keepcnt>45</keepcnt>         
    </tcp>
  </remote>

  ### ROOTCHECK ###
  <rootcheck>
    <sleep>47</sleep>
  </rootcheck>

  ### SCA ###
  <sca>
    <request_db_interval>7</request_db_interval>  
    <commands>
      <remote>1</remote> 
      <timeout>17</timeout>      
    </commands>
  </sca>

    ### SYSCHECK ###
  <syscheck>
    <sleep>2</sleep>                                    
    <sleep_after>77</sleep_after>                       
    <rt_delay>17</rt_delay>                             
    <!--max_fd_win_rt>197</max_fd_win_rt-->                  
    <max_audit_entries>192</max_audit_entries>          
    <default_max_depth>189</default_max_depth>          
    <symlink_scan_interval>514</symlink_scan_interval>  
    <file_size_max>777</file_size_max>                  
    <log_level>2</log_level>                                
  </syscheck>

  ### AUTH ###
  <auth>
    <timeout>
      <seconds>2</seconds>                 
      <microseconds>17</microseconds>          
    </timeout>
    <log_level>2</log_level>              
  </auth>

  ### DATABASE_OUTPUT ###
  <database_output>                                     
    <reconnect_attempts>7</reconnect_attempts>    
  </database_output>

  ### CLUSTER ###
  <cluster>
    <log_level>2</log_level>                        
  </cluster>

  ### WAZUH_COMMAND ###
  <wodle name="command">
    <remote_commands>1</remote_commands>
  </wodle>

  ### NEW MODULES ###
  ### ANALYSIS ###
  <analysis>
    <default_timeframe>77</default_timeframe>   
    <stats>   
      <maxdiff>777777</maxdiff>           
      <mindiff>777</mindiff>            
      <percent_diff>77</percent_diff>          
    </stats>    
    <fts>   
      <list_size>17</list_size>       
      <min_size_for_str>7</min_size_for_str>    
    </fts>    
    <log_fw>0</log_fw>                                  
    <decoder_order_size>77</decoder_order_size>         
    <!--geoip_jsonout>0</geoip_jsonout-->                    
    <labels>    
      <cache_maxage>0</cache_maxage>                    
      <show_hidden>1</show_hidden>                      
    </labels>   
    <rlimit_nofile>7777</rlimit_nofile>                 
    <min_rotate_internal>777</min_rotate_internal>      
    <threads>   
      <event>5</event>                                  
      <syscheck>5</syscheck>                            
      <syscollector>5</syscollector>                    
      <rootcheck>5</rootcheck>                          
      <sca>5</sca>                                      
      <hostinfo>5</hostinfo>                            
      <winevent>5</winevent>                            
      <rule_matching>5</rule_matching>                  
    </threads>    
    <queue_size>    
      <decode_event>7777</decode_event>                              
      <decode_syscheck>7777</decode_syscheck>                        
      <decode_syscollector>7777</decode_syscollector>                
      <decode_rootcheck>7777</decode_rootcheck>                      
      <decode_sca>7777</decode_sca>                                  
      <decode_hostinfo>7777</decode_hostinfo>                        
      <decode_winevent>7777</decode_winevent>                        
      <decode_output>7777</decode_output>                            
      <archive>7777</archive>                          
      <statistical>7777</statistical>                  
      <alerts>7777</alerts>                            
      <firewall>7777</firewall>                        
      <fts>7777</fts>                                  
    </queue_size>     
    <state_interval>7</state_interval>                  
    <log_level>2</log_level>                                
  </analysis>

  ### LOGCOLLECTOR ###
  <logcollector>
    <remote_commands>1</remote_commands>               
      <sock_fail_time>77</sock_fail_time>              
      <queue_size>777</queue_size>                     
      <sample_log_length>77</sample_log_length>        
      <files>
        <loop_timeout>7</loop_timeout>                
        <open_attempts>7</open_attempts>              
        <vcheck>55</vcheck>                           
        <max_lines>777</max_lines>                    
        <max_files>777</max_files>                    
        <input_threads>7</input_threads>              
        <rlimit_nofile>2019</rlimit_nofile>            
        <exclude_interval>77777</exclude_interval>    
      </files>
      <reload>
        <force>1</force>                              
        <interval>77</interval>                       
        <delay>578</delay>                            
      </reload>
      <log_level>2</log_level>                            
  </logcollector>

  <database>
    <global_db>
      <sync_agents>0</sync_agents>                             
      <sync_rootcheck>0</sync_rootcheck>                          
      <full_sync>1</full_sync>                                    
      <real_time>0</real_time>                          
      <interval>51</interval>   
      <max_queued_events>1</max_queued_events> 
    </global_db>
    <worker_pool_size>6</worker_pool_size>              
    <commit_time>10</commit_time>                        
    <open_db_limit>33</open_db_limit>                   
    <rlimit_nofile>4569</rlimit_nofile>   
    <thread_stack_size>6598</thread_stack_size>              
    <log_level>2</log_level>     
  </database>

  ### WAZUH_MODULES ###
  <modules>
    <task_nice>7</task_nice>                           
    <max_eps>77</max_eps>                              
    <kill_timeout>23</kill_timeout>                    
    <log_level>2</log_level>                               
  </modules>

  ### WAZUH_DOWNLOAD ###
  <download>
    <enabled>0</enabled>  
  </download>

  ### EXEC ###  
  <exec>  
    <request_timeout>37</request_timeout>  
    <max_restart_lock>378</max_restart_lock>
    <log_level>2</log_level>  
  </exec>         

  ### MAIL ###          
  <mail>          
    <strict_checking>0</strict_checking>                
    <grouping>0</grouping>                              
    <full_subject>1</full_subject>                      
    <!--geoip>0</geoip-->                                    
  </mail>

  ### INTEGRATOR ###
  <integrator>
    <log_level>2</log_level>                                
  </integrator>
```

**Min/Max compatible versions**
3.12.0 - Current

**Test**
- [ ] No configuration error thrown by any option.
- [ ] Check the values are correct. It can be tested checking the on demand configuration and/or the expected behaviour of every option. The on demand configuration is also defined in the Wazuh documentation.

## INT003

**Short description**

Legacy compatibility

**Category**

Internal options deprecation

**Subcategory**

Legacy compatibility

**Description**

The options set in the `ossec.conf`

**Configuration sample**

Default configuration (no options set). Non-existent or empty `internal_options.conf` and `local_internal_options.conf`.

**Min/Max compatible versions**
3.12.0 - Current

**Configuration sample**

Copy the old ``ìnternal_options.conf`` (or its content to ``local_internal_options.conf``) to its original folder.

**Test**

- [ ] Check that every old internal option in `internal_options.conf` or `local_internal_options.conf` still readable.
- [ ] Check the `ossec.conf`/default options values are overwritten by the values specified in `internal_options.conf`/`local_internal_options.conf`.

## INT004

**Short description**

Installation/Upgrade

**Category**

Internal options deprecation

**Subcategory**

Installation/Upgrade

**Description**

On a fresh installation both `internal_options.conf` and `local_internal_options.conf` files must not be installed.
On updates (if they exist) the `local_internal_options.conf` must remain untouched and the `internal_options.conf` must be deleted.

**Min/Max compatible versions**
3.12.0 - Current

**Test**

- [ ] Ubuntu manager: Check sources/packages installation/update works as expected.
- [ ] CentOS manager: Check sources/packages installation/update works as expected.
- [ ] Ubuntu agent: Check sources/packages installation/update works as expected.
- [ ] CentOS agent: Check sources/packages installation/update works as expected.
- [ ] Windows agent: Check sources/packages installation/update works as expected (`.exe`).
- [ ] Solaris 10/11 agent: Check sources/packages installation/update works as expected.
- [ ] HP-UX agent: Check sources/packages installation/update works as expected.
- [ ] AIX agent: Check sources/packages installation/update works as expected.

## INT005

**Short description**

Config on demand visualization

**Category**

Internal options deprecation

**Subcategory**

API visualization

**Description**

The options values must be seen in the on demand configuration (API) of Wazuh (check documentation).

**Log sample**

``` 
curl -u foo:bar -k -X GET "http://127.0.0.1:55000/agents/000/config/logcollector/logcollector?pretty"
{
   "error": 0,
   "data": {
      "logcollector": {
         "remote_commands": "disabled",
         "sock_fail_time": 300,
         "queue_size": 1024,
         "sample_log_length": 64,
         "files": {
            "loop_timeout": 2,
            "open_attempts": 8,
            "vcheck": 64,
            "max_lines": 10000,
            "max_files": 1000,
            "input_threads": 4,
            "rlimit_nofile": 1100,
            "exclude_interval": 86400
         },
         "reload": {
            "force": "disabled",
            "interval": 64,
            "delay": 1000
         },
         "thread_stack_size": 8192,
         "log_level": 0
      }
   }
}
```

**Min/Max compatible versions**
3.12.0 - Current

## INT006

**Short description**

App visualization

**Category**

Internal options deprecation

**Subcategory**

App visualization

**Description**

The options values must be seen in the Wazuh App (check documentation).

**Min/Max compatible versions**
3.12.0 - Current
