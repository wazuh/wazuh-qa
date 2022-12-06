import subprocess as sbp

class ContentMigrationTool():

    def __init__(self, args):
        self.working_dir = '/var/wazuh'
        self.executable = f"{self.working_dir}/bin/content_migration"
        self.args = args


    def run(self):
        """Method to run the Content Migration tool with specified parameters and get the output.
        """
        output = None
        cmd = ' '.join([self.executable, self.args])
        proc = sbp.Popen(cmd, shell=True, stdout=sbp.PIPE, stderr=sbp.PIPE)
        out, err = proc.communicate()

        if err:
            output = err.decode()
        else:
            output = out.decode()

        return output
