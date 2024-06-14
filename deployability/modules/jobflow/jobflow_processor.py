# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import concurrent.futures
import graphlib
import json
import time
import yaml
import os

from pathlib import Path
from itertools import product

from jobflow.logger.logger import logger
from jobflow.schema_validator import SchemaValidator
from jobflow.task import Task, TASKS_HANDLERS

class JobFlowFile:
    """Class for loading and processing a JobFlow workflow file."""
    schema_path = Path(__file__).parent / 'schemas' / 'schema_v1.json'

    def __init__(self, jobflow_file_path: Path | str, schema_path: Path | str = None) -> None:
        self.schema_path = schema_path or self.schema_path
        self.__validate_schema(jobflow_file_path)
        self.jobflow_raw_data = self.__load_workflow(jobflow_file_path)
        self.task_collection = self.__process_workflow()
        self.__static_workflow_validation()

    def __validate_schema(self, jobflow_file: Path | str) -> None:
        """
        Validate the workflow file against the schema.

        Args:
            jobflow_file (Path | str): Path to the workflow file.
        """
        try:
            logger.debug(f"Validating input file: {jobflow_file}")
            validator = SchemaValidator(self.schema_path, jobflow_file)
            validator.preprocess_data()
            validator.validateSchema()
        except Exception as e:
            logger.error("Error while validating schema [%s] with error: %s", self.schema_path, e)
            raise

    def __load_workflow(self, file_path: str) -> dict:
        """
        Load the workflow data from a file.

        Args:
            file_path (str): Path to the workflow file.

        Returns:
            dict: workflow data.
        """

        if not os.path.exists(file_path):
            raise FileNotFoundError(f'File "{file_path}" not found.')

        logger.debug(f"Loading workflow file: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)

    def __process_workflow(self):
        """Process the workflow and return a list of tasks."""
        logger.debug("Process workflow.")
        task_collection = []
        variables = self.jobflow_raw_data.get('variables', {})
        for task in self.jobflow_raw_data.get('tasks', []):
            task_collection.extend(self.__expand_task(task, variables))

        if not task_collection:
            raise ValueError("No tasks found in the workflow.")
        return task_collection

    def __replace_placeholders(self, element: str, values: dict, parent_key: str = None):
        """
        Recursively replace placeholders in a dictionary or list.

        Args:
            element (Any): The element to process.
            values (dict): The values to replace placeholders.
            parent_key (str): The parent key for nested replacements.

        Returns:
            Any: The processed element.
        """
        if isinstance(element, dict):
            return {key: self.__replace_placeholders(value, values, key) for key, value in element.items()}
        if isinstance(element, list):
            return [self.__replace_placeholders(sub_element, values, parent_key) for sub_element in element]
        if isinstance(element, str):
            return element.format_map(values)
        return element

    def __expand_task(self, task: dict, variables: dict):
        """
        Expand a task with variable values.

        Args:
            task (dict): The task to expand.
            variables (dict): Variable values.

        Returns:
            List[dict]: List of expanded tasks.
        """
        expanded_tasks = []

        if 'foreach' in task:
            loop_variables = task.get('foreach', [{}])

            variable_names = [loop_variable_data.get('variable') for loop_variable_data in loop_variables]
            as_identifiers = [loop_variable_data.get('as') for loop_variable_data in loop_variables]

            variable_values = [variables.get(name, []) for name in variable_names]

            for combination in product(*variable_values):
                variables_with_items = {**variables, **dict(zip(as_identifiers, combination))}
                expanded_tasks.append(self.__replace_placeholders(task, variables_with_items))
        else:
            expanded_tasks.append(self.__replace_placeholders(task, variables))

        return expanded_tasks

    def __static_workflow_validation(self):
        """Validate the workflow against static criteria."""
        def check_duplicated_tasks(self):
            """Validate task name duplication."""
            task_name_counts = {task['task']: 0 for task in self.task_collection}

            for task in self.task_collection:
                task_name_counts[task['task']] += 1

            duplicates = [name for name, count in task_name_counts.items() if count > 1]

            if duplicates:
                raise ValueError(f"Duplicated task names: {', '.join(duplicates)}")

        def check_not_existing_tasks(self):
            """Validate task existance."""
            task_names = {task['task'] for task in self.task_collection}

            for dependencies in [task.get('depends-on', []) for task in self.task_collection]:
                non_existing_dependencies = [dependency for dependency in dependencies if dependency not in task_names]
                if non_existing_dependencies:
                    raise ValueError(f"Tasks do not exist: {', '.join(non_existing_dependencies)}")

        validations = [check_duplicated_tasks, check_not_existing_tasks]
        for validation in validations:
            validation(self)


class DAG():
    """Class for creating a dependency graph."""
    def __init__(self, task_collection: list, reverse: bool = False):
        self.task_collection = task_collection
        self.reverse = reverse
        self.dag, self.dependency_tree = self.__build_dag()
        self.to_be_canceled = set()
        self.finished_tasks_status = {
            'failed': set(),
            'canceled': set(),
            'successful': set(),
        }
        self.execution_plan = self.__create_execution_plan(self.dependency_tree)
        self.dag.prepare()

    def is_active(self) -> bool:
        """Check if the DAG is active."""
        return self.dag.is_active()

    def get_available_tasks(self) -> list:
        """Get the available tasks."""
        return self.dag.get_ready()

    def get_execution_plan(self) -> dict:
        """Get the execution plan."""
        return self.execution_plan

    def set_status(self, task_name: str, status: str):
        """Set the status of a task."""
        self.finished_tasks_status[status].add(task_name)
        self.dag.done(task_name)

    def should_be_canceled(self, task_name: str) -> bool:
        """Check if a task should be canceled."""
        return task_name in self.to_be_canceled

    def __build_dag(self):
        """Build a dependency graph for the tasks."""
        dependency_dict = {}
        dag = graphlib.TopologicalSorter()

        for task in self.task_collection:
            task_name = task['task']
            dependencies = task.get('depends-on', [])

            if self.reverse:
                for dependency in dependencies:
                    dag.add(dependency, task_name)
            else:
                dag.add(task_name, *dependencies)

            dependency_dict[task_name] = dependencies

        return dag, dependency_dict

    def cancel_dependant_tasks(self, task_name, cancel_policy) -> None:
        """Cancel all tasks that depend on a failed task."""
        def get_all_task_set(tasks):
            task_set = set()

            for task, sub_tasks in tasks.items():
                task_set.add(task)
                task_set.update(get_all_task_set(sub_tasks))

            return task_set

        if cancel_policy == 'continue':
            return

        not_cancelled_tasks = self.finished_tasks_status['failed'].union(self.finished_tasks_status['successful'])
        for root_task, sub_tasks in self.execution_plan.items():
            task_set = get_all_task_set({root_task: sub_tasks})
            if cancel_policy == 'abort-all':
                self.to_be_canceled.update(task_set)
            elif cancel_policy == 'abort-related-flows':
                if task_name in task_set:
                    self.to_be_canceled.update(task_set - not_cancelled_tasks)
            else:
                raise ValueError(f"Unknown cancel policy '{cancel_policy}'.")

    def __create_execution_plan(self, dependency_dict: dict) -> dict:

        execution_plan = {}

        def get_root_tasks(dependency_dict: dict) -> set:
            """Get root tasks from the dependency dictionary."""
            all_tasks = set(dependency_dict.keys())
            dependent_tasks = set(dep for dependents in dependency_dict.values() for dep in dependents)
            return all_tasks - dependent_tasks

        def get_subtask_plan(task_name: str, dependency_dict: dict, level: int = 0) -> dict:
            """Create the execution plan recursively as a dictionary."""
            if task_name not in dependency_dict:
                return {task_name: {}}

            dependencies = dependency_dict[task_name]
            plan = {task_name: {}}

            for dependency in dependencies:
                sub_plan = get_subtask_plan(dependency, dependency_dict, level + 1)
                plan[task_name].update(sub_plan)

            return plan

        root_tasks = get_root_tasks(dependency_dict)
        for root_task in root_tasks:
            execution_plan.update(get_subtask_plan(root_task, dependency_dict))

        return execution_plan


class JobFlowProcessor:
    """Class for processing a workflow."""

    def __init__(self, jobflow_file: str, dry_run: bool, threads: int, log_level: str = 'INFO', schema_file: Path | str = None):
        """
        Initialize JobFlowProcessor.

        Args:
            jobflow_file (str): Path to the workflow file (YAML format).
            dry_run (bool): Display the plan without executing tasks.
            threads (int): Number of threads to use for parallel execution.
            log_level (str): Log level.
            schema_file (Path | str): Path to the schema file (YAML format).
        """
        logger.setLevel(log_level)
        # Initialize the instance variables.
        self.task_collection = JobFlowFile(jobflow_file, schema_file).task_collection
        self.dry_run = dry_run
        self.threads = threads

    def execute_task(self, dag: DAG, task: dict, action) -> None:
        """Execute a task."""
        task_name = task['task']
        if dag.should_be_canceled(task_name):
            logger.warning("[%s] Skipping task due to dependency failure.", task_name)
            dag.set_status(task_name, 'canceled')
        else:
            try:
                task_object = self.create_task_object(task, action)

                logger.info("[%s] Starting task.", task_name)
                start_time = time.time()
                task_object.execute()
                logger.info("[%s] Finished task in %.2f seconds.", task_name, time.time() - start_time)
                dag.set_status(task_name, 'successful')
            except KeyboardInterrupt as e:
                logger.error("[%s] Task failed with error: %s", task_name, e)
                dag.set_status(task_name, 'failed')
                dag.cancel_dependant_tasks(task_name, task.get('on-error', 'abort-related-flows'))
                raise KeyboardInterrupt
            except Exception as e:
                logger.error("[%s] Task failed with error: %s", task_name, e)
                dag.set_status(task_name, 'failed')
                dag.cancel_dependant_tasks(task_name, task.get('on-error', 'abort-related-flows'))
                raise


    def create_task_object(self, task: dict, action) -> Task:
        """Create and return a Task object based on task type."""
        task_type = task[action]['this']

        task_handler = TASKS_HANDLERS.get(task_type)

        if task_handler is not None:
            return task_handler(task['task'], task[action]['with'])

        raise ValueError(f"Unknown task type '{task_type}'.")

    def execute_tasks_parallel(self, dag: DAG, reverse: bool = False) -> None:
        """Execute tasks in parallel."""
        logger.info("Executing tasks in parallel.")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = self.generate_futures(dag, executor, reverse)
                concurrent.futures.wait(futures.values())
        except KeyboardInterrupt:
            logger.error("User interrupt detected. Aborting execution...")
            self.execute_tasks_parallel(dag, reverse=True)

    def generate_futures(self, dag: DAG, executor, reverse: bool = False):
        futures = {}

        while True:
            if not dag.is_active():
                break

            for task_name in list(dag.get_available_tasks()):
                task = next(t for t in self.task_collection if t['task'] == task_name)
                action = 'cleanup' if reverse and 'cleanup' in task else 'do'
                if reverse and 'cleanup' not in task:
                    dag.set_status(task_name, 'successful')
                else:
                    future = executor.submit(self.execute_task, dag, task, action)
                    futures[task_name] = future

        return futures


    def run(self) -> None:
        """Main entry point."""
        try:
            if not self.dry_run:
                logger.info("Executing DAG tasks.")
                dag = DAG(self.task_collection)
                self.execute_tasks_parallel(dag)

                logger.info("Executing Reverse DAG tasks.")
                reversed_dag = DAG(self.task_collection, reverse=True)
                reversed_dag.to_be_canceled = dag.to_be_canceled - dag.finished_tasks_status["successful"]
                self.execute_tasks_parallel(reversed_dag, reverse=True)
            else:
                dag = DAG(self.task_collection)
                logger.info("Execution plan: %s", json.dumps(dag.get_execution_plan(), indent=2))


        except Exception as e:
            logger.error("Error in workflow: %s", e)


    def handle_interrupt(self, signum, frame):
        logger.error("User interrupt detected. End process...")
        raise KeyboardInterrupt("User interrupt detected. End process...")

    def abort_execution(self, futures) -> None:
        """Abort the execution of tasks."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for future in concurrent.futures.as_completed(futures.values()):
                try:
                    _ = future.result()
                except Exception as e:
                    logger.error("Error in aborted task: %s", e)
            executor.shutdown(wait=False, cancel_futures=True)
