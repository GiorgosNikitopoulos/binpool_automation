import docker
import argparse
import pdb
from parse import *
import os

def exit_container(container):
    container.stop()
    container.remove()

def extract_deb(link, image):
    #Create Docker Client
    client = docker.from_env()

    #Spawn container
    container = client.containers.run(image, detach=True, tty=True, name="test_container")
    
    #Download Material
    #command = "dget -u --insecure https://snapshot.debian.org/archive/debian/20160917T223122Z/pool/main/o/openjpeg2/openjpeg2_2.1.0-2%2Bdeb8u1.dsc"
    command = f"dget -u --insecure {link}"
    exec_log = client.api.exec_create(container.id, command)
    output = client.api.exec_start(exec_log['Id'])
    
    #Get the project name and directory name
    project, directory = search("info: extracting {} in {}\n", output.decode())

    #Install dependencies
    command = "apt build-dep . -y"
    exec_log = client.api.exec_create(container.id, 
                                      command, workdir=f"/usr/src/app/{directory}") #Workdir change
    output = client.api.exec_start(exec_log['Id'])
    print(output)
    try:
        done = search("\r\n\r\ndone.\r\ndone.\r\n", output.decode())
    except Exception as e:
        print(e)
        exit_container(container)
        return False


    print(done)

    #Build
    command = "dpkg-buildpackage -us -uc"
    exec_log = client.api.exec_create(container.id, 
                                      command, workdir=f"/usr/src/app/{directory}") #Workdir change
    output = client.api.exec_start(exec_log['Id'])

    #Create output_directory
    command = "mkdir output_directory"
    exec_log = client.api.exec_create(container.id, 
                                      command) 
    output = client.api.exec_start(exec_log['Id'])


    #Copy .deb to output_directory
    command = "/bin/sh -c 'cp *.deb output_directory/'"
    exec_log = client.api.exec_create(container.id, 
                                      command)
    output = client.api.exec_start(exec_log['Id'])

    #Copy output_directory to host
    bits, stat = container.get_archive("/usr/src/app/output_directory/")
    os.makedirs("debs", exist_ok=True)
    with open(f"debs/{directory}", 'wb') as f:
        for chunk in bits:
            f.write(chunk)
    
    
    #Remove container
    exit_container(container)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a list of links and extract .deb files")

    # Add argument to accept a file path
    parser.add_argument('--input_file', type=str, help='Path to the input link file')
    parser.add_argument('--image', type=str, help='Path to the input link file')

    args = parser.parse_args()

    with open(args.input_file, 'r') as f:
        links = f.read()

    for link in (links.split()):
        extract_deb(link, args.image)
