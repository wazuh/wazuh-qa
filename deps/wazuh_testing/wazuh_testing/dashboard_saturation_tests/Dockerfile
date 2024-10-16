# Use an official Python base image
FROM python:3.13.0-slim-bookworm

# ENV Variables
ENV WORK_PATH=/app
ENV APP_PATH=/dashboard_saturation_tests

# Set the working directory
WORKDIR ${WORK_PATH}

# Install curl
RUN apt-get update && \
    apt-get install -y curl coreutils

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

# Install Artillery and Playwright
RUN npm install -g artillery playwright

# Install Playwright dependencies
RUN npm install @playwright/test && \
    npx playwright install-deps

# Copy files and folders to the container
COPY . ${WORK_PATH}/${APP_PATH}

# Set the working directory
WORKDIR ${WORK_PATH}/${APP_PATH}

# Install Python Dependencies
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install .

# Default command
CMD ["sh", "-c", "tail -f /dev/null"]
