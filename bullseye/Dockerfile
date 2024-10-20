# Use Debian base image
FROM debian:bullseye

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages: 
# - build-essential for C project compilation (gcc, g++, make, etc.)
# - python3 and pip for running the Python program
# - git to pull C project from a repository (optional)
# - other utilities such as wget and curl if needed
RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /usr/src/app

# Copy your Python program and C project files into the container
#COPY ./python_program /usr/src/app/python_program
#COPY ./c_project /usr/src/app/c_project

# Install any Python dependencies (if needed)
#RUN pip3 install -r python_program/requirements.txt

# Assuming your Python program builds the C project, 
# expose any required commands (like running the Python script)
#CMD ["python3", "python_program/install_c_project.py"]
CMD ["tail", "-f", "/dev/null"]

