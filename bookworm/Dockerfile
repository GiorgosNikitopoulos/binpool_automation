# Use Debian Bookworm as the base image
FROM debian:bookworm

# Set non-interactive frontend
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install required packages
RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade all packages to the latest versions available
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Install any additional packages needed
RUN apt-get update && apt-get install -y \
    devscripts \
    quilt \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/src/app

# Copy Python and C project files into the container
# Uncomment and adjust paths as necessary
#COPY ./python_program /usr/src/app/python_program
#COPY ./c_project /usr/src/app/c_project

# Install Python dependencies if required (adjust path as necessary)
#RUN pip3 install -r python_program/requirements.txt

# Default command to keep container running or run the main program
CMD ["tail", "-f", "/dev/null"]
# To run the Python script, replace with:
# CMD ["python3", "python_program/install_c_project.py"]
