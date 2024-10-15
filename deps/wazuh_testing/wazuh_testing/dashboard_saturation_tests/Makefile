# Variables
CONSOLE=/bin/bash
APP=dashboard_saturation_tests
DATA=data
WORK=/app
ARTIFACTS=artifacts
LOGS=logs
SCREENSHOTS=screenshots
CSV=csv

.PHONY: init
init: rm purge build run ## Recreate Containers
.PHONY: test
test: exec artifacts ## Execute Tests and Collect Results
.PHONY: build
build: ## Build the Docker Image
	docker build -t $(APP) .
.PHONY: run
run: ## Run the Docker container
	docker run --name $(APP) -d $(APP)
.PHONY: bash
bash: ## Accessing the Container Console
	docker exec -it $(APP) $(CONSOLE)
.PHONY: exec
exec: ## Running Dashboard Saturation Tests
	docker exec -it $(APP) $(CONSOLE) -c "dashboard-saturation-tests ${COMMAND_OPTIONS}" || true
.PHONY: update
update: ## Update Data Content in Container (Testing Purposes Only)
	docker exec -it $(APP) $(CONSOLE) -c "rm -rfv ${DATA}" || true
	docker cp $(shell pwd)/$(DATA) $(APP):/app/${APP}/${DATA}
	docker exec -it $(APP) $(CONSOLE) -c "python3 -m pip install ."
.PHONY: artifacts
artifacts: ## Copy Test Results to Volume
	mkdir -p $(ARTIFACTS)
	docker cp $(APP):/app/${APP}/${LOGS} $(shell pwd)/$(ARTIFACTS)
	docker cp $(APP):/app/${APP}/${SCREENSHOTS} $(shell pwd)/$(ARTIFACTS)
	docker cp $(APP):/app/${APP}/${CSV} $(shell pwd)/$(ARTIFACTS)
.PHONY: rm
rm: ## Remove Image, Container and Volume
	rm -rfv $(ARTIFACTS)
	docker rm -v -f $(APP) || true
	docker rmi $(APP) || true
.PHONY: clean
clean: ## Delete Docker Container and Volume
	docker rm -v -f $(APP) || true
.PHONY: purge
purge: ## Purge All Docker Resources
	docker system prune -a -f
.PHONY: destroy
destroy: rm purge ## Destroy All Docker Resources
.PHONY: help
help: ## Display Help Message
	@cat $(MAKEFILE_LIST) | grep -e "^[a-zA-Z_\-]*: *.*## *" | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'