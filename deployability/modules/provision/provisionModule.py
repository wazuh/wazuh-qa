from abc import ABC, abstractmethod

class ProvisionModule(ABC):
	@abstractmethod
	def run(self):
		"""
		Run Provision Module.

		Args:
				payload: InputPayload - model with the input data.

		Model:
				inventory_agent: Path | None
				inventory_manager: Path | None
				inventory: Path | None
				install: list | None
				custom_credentials: str | None
				manager_ip: IPvAnyAddress | None
		"""
		pass

	@abstractmethod
	def handle_package(self, package):
		"""
		Handle Package.

		Args:
				package: Data with the package to install.
		"""
		pass

	@abstractmethod
	def update_status(self, status):
		"""
		Update Status.

		Args:
				status: Result status.
		"""
		pass

	@abstractmethod
	def node_dependencies():
		"""
		Install python dependencies on Worker node.
		"""
		pass

	@abstractmethod
	def install_host_dependencies(self):
		"""
		Install python dependencies on host.

		Args:
				ansible_data: Data with the ansible configuration.
		"""