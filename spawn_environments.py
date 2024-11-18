import docker
import argparse
import pdb
from parse import *
import os

def environment_vars(flag_level):
    environment = {"CFLAGS": f"-O{flag_level}",
                   "CXXFLAGS": f"-O{flag_level}",
                   "FFLAGS": f"-O{flag_level}",
                   "DEB_BUILD_OPTIONS": "nostrip debug"}
    return environment

def exit_container(container):
    container.stop()
    container.remove()

def build(link, image, patch, opt = 1):
    ''' This function test builds a repository and returns the 
        list of patches that can be applied to it by quilt'''
    #Create Docker Client
    client = docker.from_env()

    #Spawn container
    container = client.containers.run(image, detach=True, tty=True, name=f"{image}_container")
    
    #Download Material
    #command = "dget -u --insecure https://snapshot.debian.org/archive/debian/20160917T223122Z/pool/main/o/openjpeg2/openjpeg2_2.1.0-2%2Bdeb8u1.dsc"
    command = f"dget -u --insecure {link}"
    exec_log = client.api.exec_create(container.id, command)
    output = client.api.exec_start(exec_log['Id'])
    
    #Get the project name and directory name
    try:
        project, directory = search("info: extracting {} in {}\n", output.decode())
        print(f"This is {project} and {directory}")
    except Exception as e:
        print(e)
        exit_container(container)
        return False

    #Quilt pop the patch
    if patch != None:
        command = f"quilt pop debian/patches/{patch}"
        exec_log = client.api.exec_create(container.id, 
                                          command, workdir=f"/usr/src/app/{directory}") #Workdir change
        output = client.api.exec_start(exec_log['Id'])
    #pdb.set_trace()

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


    #Build
    command = "dpkg-buildpackage -us -uc"
    exec_log = client.api.exec_create(container.id, 
                                      command, environment = environment_vars(opt), #Create environment variables with opt equal to the current runs opts
                                      workdir=f"/usr/src/app/{directory}") #Workdir change
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


    ##See if it produced the debs
    command = "/bin/sh -c 'ls *.deb output_directory/ | wc -l'"
    exec_log = client.api.exec_create(container.id, 
                                      command)
    output = client.api.exec_start(exec_log['Id'])
    try:
        ls_result = int(output)
    except ValueError:
        exit_container(container)
        return None

    if ls_result <= 3: 
        #Then no .deb file was created
        #Return None and do not extract anything
        exit_container(container)
        return None


    #Copy output_directory to host
    bits, stat = container.get_archive("/usr/src/app/output_directory/")
    os.makedirs("debs", exist_ok=True)

    if patch != None:
        patch = patch.decode('utf-8')
        patch = patch.split(".")[0]
    else:
        patch = "None"

    with open(f"debs/{directory}_{patch}_opt{opt}", 'wb') as f:
        for chunk in bits:
            f.write(chunk)
    
    
    #Remove container
    exit_container(container)
    
    return


def initial_build(link, image):
    ''' This function test builds a repository and returns the 
        list of patches that can be applied to it by quilt'''
    #Create Docker Client
    client = docker.from_env()

    #Spawn container
    container = client.containers.run(image, detach=True, tty=True, name=f"{image}_container")
    
    #Download Material
    #command = "dget -u --insecure https://snapshot.debian.org/archive/debian/20160917T223122Z/pool/main/o/openjpeg2/openjpeg2_2.1.0-2%2Bdeb8u1.dsc"
    command = f"dget -u --insecure {link}"
    exec_log = client.api.exec_create(container.id, command)
    output = client.api.exec_start(exec_log['Id'])
    
    #pdb.set_trace()
    #Get the project name and directory name
    try:
        project, directory = search("info: extracting {} in {}\n", output.decode())
        print(f"This is {project} and {directory}")
    except Exception as e:
        print(e)
        exit_container(container)
        return False

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


    ##See if it produced the debs
    command = "/bin/sh -c 'ls *.deb output_directory/ | wc -l'"
    exec_log = client.api.exec_create(container.id, 
                                      command)
    output = client.api.exec_start(exec_log['Id'])
    try:
        ls_result = int(output)
    except ValueError:
        #Then no .deb file was created
        #Return None and do not extract anything
        exit_container(container)
        return None

    if ls_result <= 3: 
        #Then no .deb file was created
        #Return None and do not extract anything
        exit_container(container)
        return None

    ##Which patches are in there
    ##TODO Change this to do all patch files
    command = "/bin/sh -c 'ls -1a CVE-*'"
    exec_log = client.api.exec_create(container.id, 
                                      command, workdir=f"/usr/src/app/{directory}/debian/patches/")
    output = client.api.exec_start(exec_log['Id'])

    ##Check if ls is empty
    if "No such file or directory" in str(output):
        exit_container(container)
        return None
    cve_patches = output.splitlines()

    ##TODO Get list and cat all files to find CVE-NNNN-NNNNN pattern in a loop


    #Copy output_directory to host
    bits, stat = container.get_archive("/usr/src/app/output_directory/")
    os.makedirs("debs", exist_ok=True)
    with open(f"debs/{directory}", 'wb') as f:
        for chunk in bits:
            f.write(chunk)
    
    
    #Remove container
    exit_container(container)
    
    if len(cve_patches) > 0:
        pass
    else:
        cve_patches = None

    return cve_patches

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a list of links and extract .deb files")

    # Add argument to accept a file path
    parser.add_argument('--input_file', type=str, help='Path to the input link file')
    parser.add_argument('--image', type=str, help='Path to the input link file')

    args = parser.parse_args()

    with open(args.input_file, 'r') as f:
        links = f.read()

    for link in (links.split()):
        patches = initial_build(link, args.image)
        if patches == None or patches == False:
            continue
        #No patches is a patch version too
        patches = [None] + patches
        for patch in patches:
            for opt in [1, 2, 3]:
                build(link, args.image, patch, opt)

