ruby_block "Save node attributes" do
    block do
      File.write("/tmp/kitchen_chef_node.json", node.to_json)
    end
end