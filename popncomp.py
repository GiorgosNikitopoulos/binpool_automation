import docker
import inspect
import argparse
import pdb
from parse import *
import os
import re
import sys
from func_timeout import func_timeout, FunctionTimedOut
import concurrent.futures
from datetime import datetime



def process_build(link, patch, filename, patch_file, opt):
    _id = os.urandom(4).hex()
    container = run_container(args.image, f"{args.image}_container_{_id}")
    build(link, container, patch, filename, opt, patch_file)
    return (link, patch, filename, opt)  # Return results if needed

def get_batches(lst, batch_size):
    for i in range(0, len(lst), batch_size):
        yield lst[i:i + batch_size]

def process_link(link, args):
    # Create random suffix and spawn container
    _id = os.urandom(4).hex()
    container = run_container(args.image, f"{args.image}_container_{_id}")
    patches, patch_files, patch_contents = initial_build(link, container, args)

    if not patches:
        return None  # Skip this link if no patches are found

    # No patches is a patch version too
    patches = [None] + patches
    patch_files = [None] + patch_files
    patch_contents = [None] + patch_contents

    results = []
    for patch, filename, patch_file in zip(patches, patch_files, patch_contents):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            # Create futures for all combinations of patches and optimization levels
            futures = [
                executor.submit(process_build, link, patch, filename, patch_file, opt)
                for patch, filename, patch_file in zip(patches, patch_files, patch_contents)
                for opt in [0, 1, 2, 3]
            ]
            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
    return results

def get_exec_output(client, exec_log):
    return client.api.exec_start(exec_log['Id'])


def handle_ctrl_c_with_locals(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print("\nCtrl+C caught!")
            print("Accessing local variables at the time of interrupt:")

            # Get the current exception traceback
            tb = sys.exc_info()[2]
            while tb.tb_next:  # Traverse to the last frame (function that triggered Ctrl+C)
                frame = tb.tb_frame
                local_vars = frame.f_locals
                func_name = frame.f_code.co_name
                if "build" not in func_name:
                    tb = tb.tb_next
                    continue

                print(f"Caught interrupt in {func_name}")
                for var_name, value in local_vars.items():
                    print(f"  {var_name}: {value}")
                    if var_name == 'container':
                        print(f"Exiting container {value.name}, please wait...")
                        exit_container(value)
                        sys.exit(1)
    return wrapper


def log_function_call(func):
    def wrapper(*args, **kwargs):
        func_name = func.__name__

        sig = inspect.signature(func)
        bound_args = sig.bind(*args, **kwargs)
        bound_args.apply_defaults()  # Ensure default values are included

        print(f"Function '{func_name}' called with arguments: ")
        for k,v in bound_args.arguments.items():
            print(f"\t{k}: {v}")
            if hasattr(v, 'name'):
                print(f"\t\t{v.name}")

        return func(*args, **kwargs)

    return wrapper


def environment_vars(flag_level):
    environment = {"CFLAGS": f"-O{flag_level}",
                   "CXXFLAGS": f"-O{flag_level}",
                   "FFLAGS": f"-O{flag_level}",
                   "DEB_BUILD_OPTIONS": "nostrip debug"}
    return environment


def exit_container(container):
    try:
        container.stop(timeout=60)
        container.remove(force=True)
    except Exception as e:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[ERROR {timestamp}] {e}")
        print(f"{timestamp}")



@handle_ctrl_c_with_locals
@log_function_call
def build(link, container, patch, filename, opt, patch_file):

    ''' This function test builds a repository and returns the
        list of patches that can be applied to it by quilt'''

    client = docker.from_env()

    #Download Material
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
    done_popping = False
    if patch != None:
        # get the topmost patch, max 10 depth
        max_depth = 10

        while max_depth != 0:
            command = "/bin/sh -c 'quilt top | awk -F\"/\" \"{print $NF}\"'"
            exec_log = client.api.exec_create(container.id,
                                              command, workdir=f"/usr/src/app/{directory}") #Workdir change
            output = client.api.exec_start(exec_log['Id']).decode()

            if patch in output:
                #print(f"Quilt top output contains {patch}:")
                #for line in output.splitlines():
                    #print(f"[OUTPUT] {line}")
                done_popping = True
                
                # pop a patch
                #command = "quilt pop"
                command = "quilt delete"
                exec_log = client.api.exec_create(container.id,
                                                  command,
                                                  workdir=f"/usr/src/app/{directory}")
                output = client.api.exec_start(exec_log['Id']).decode()
                break
            else:
                # pop a patch
                #command = "quilt pop"
                command = "quilt delete"
                exec_log = client.api.exec_create(container.id,
                                                  command,
                                                  workdir=f"/usr/src/app/{directory}")
                output = client.api.exec_start(exec_log['Id']).decode()
                #print(f"Quilt top does not contain {patch}, quilt pop output:")
                #for line in output.splitlines():
                    #print(f"[OUTPUT] {line}")

            max_depth -= 1


        if not done_popping and "No patch removed" in output:
            #for line in output.splitlines():
                #print(f"[OUTPUT] {line}")
            print("Error with quilt! stopping...", file=sys.stderr)
            exit_container(container)
            return None

    #Install dependencies
    print("Running apt build-dep...")
    command = "apt build-dep . -y"
    exec_log = client.api.exec_create(container.id,
                                      command, workdir=f"/usr/src/app/{directory}") #Workdir change
    output = client.api.exec_start(exec_log['Id']).decode()
    #print("Output from apt build-dep:")
    #for line in output.splitlines():
        #print(f"[OUTPUT] {line}")

    #Clean
    print("Running clean...")
    command = "/bin/sh -c 'debian/rules clean && rm -rf build'"
    exec_log = client.api.exec_create(container.id,
                                      command, workdir=f"/usr/src/app/{directory}") #Workdir change
    output = client.api.exec_start(exec_log['Id']).decode()
    #print("Output from apt build-dep:")
    #for line in output.splitlines():
        #print(f"[OUTPUT] {line}")

    #pdb.set_trace()
    #Build
    print("Running dpkg-buildpackage...")
    command = "dpkg-buildpackage -us -uc -j10"
    exec_log = client.api.exec_create(container.id,
                                      command, environment = environment_vars(opt), #Create environment variables with opt equal to the current runs opts
                                      workdir=f"/usr/src/app/{directory}") #Workdir change
    #pdb.set_trace()
    #try:
    #    output = client.api.exec_start(exec_log['Id']).decode()
    #except Exception as e:
    #    print(f"Cannot build package, error: {e}")
    #    exit_container(container)
    #    return None
    try:
        output = func_timeout(args.timeout, get_exec_output, args=(client, exec_log))
    except FunctionTimedOut:
        print("Timed out building of project")
        exit_container(container)
        client.close()
        return None


    #for line in output.splitlines():
        #print(f"[OUTPUT] {line}")

    #Create output_directory
    command = "mkdir output_directory"
    exec_log = client.api.exec_create(container.id,
                                      command)
    output = client.api.exec_start(exec_log['Id'])


    #Copy .deb to output_directory
    print("Copying .deb file")
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
        print("No .deb file was created return None and do not extract anything", file=sys.stderr)
        exit_container(container)
        return None

    if ls_result <= 3:
        #Then no .deb file was created
        #Return None and do not extract anything
        print("No .deb file was created return None and do not extract anything", file=sys.stderr)
        exit_container(container)
        return None


    #Copy output_directory to host
    bits, stat = container.get_archive("/usr/src/app/output_directory/")
    os.makedirs(f"{args.output_dir}", exist_ok=True)

    if patch != None:
        patch = patch.split(".")[0]
    else:
        patch = "None"

    patch = os.path.basename(patch)
    #Write tar
    with open(f"{args.output_dir}/{directory}_{patch}_opt{opt}", 'wb') as f:
        for chunk in bits:
            f.write(chunk)

    #Write the patch file
    if patch_file != None:
        with open(f"{args.output_dir}/{directory}_{patch}_opt{opt}.patch", 'wb') as f:
            f.write(patch_file)

    #Remove container
    exit_container(container)

    #Disconnect client
    client.close()

    return


def run_container(image, name, detach=True, tty=True):
    client = docker.from_env()
    container = client.containers.run(image, detach=detach, tty=tty, name=name)
    client.close()
    return container

@handle_ctrl_c_with_locals
@log_function_call
def initial_build(link, container, args):

    ''' This function test builds a repository and returns the
        list of patches that can be applied to it by quilt'''

    client = docker.from_env()

    # default return
    def_ret = None, None, None

    #Download Material
    #command = "dget -u --insecure https://snapshot.debian.org/archive/debian/20160917T223122Z/pool/main/o/openjpeg2/openjpeg2_2.1.0-2%2Bdeb8u1.dsc"
    command = f"dget -u --insecure {link}"
    exec_log = client.api.exec_create(container.id, command)
    output = client.api.exec_start(exec_log['Id'])

    #pdb.set_trace()
    #Get the project name and directory name
    try:
        project, directory = search("info: extracting {} in {}\n", output.decode())
        print(f"Processing {project}, {directory}")
    except Exception as e:
        print(e)
        exit_container(container)
        client.close()
        return def_ret

    #Install dependencies
    command = "apt build-dep . -y"
    exec_log = client.api.exec_create(container.id,
                                      command, workdir=f"/usr/src/app/{directory}") #Workdir change
    output = client.api.exec_start(exec_log['Id'])

    #Build
    command = "dpkg-buildpackage -us -uc -j10"
    exec_log = client.api.exec_create(container.id,
                                      command, workdir=f"/usr/src/app/{directory}") #Workdir change

    try:
        output = func_timeout(args.timeout, get_exec_output, args=(client, exec_log))
    except FunctionTimedOut:
        print("Timed out building of project")
        exit_container(container)
        client.close()
        return def_ret

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
        print("No .deb file was created return None and do not extract anything", file=sys.stderr)
        exit_container(container)
        client.close()
        return def_ret

    if ls_result <= 3:
        #Then no .deb file was created
        #Return None and do not extract anything
        print("No .deb file was created return None and do not extract anything", file=sys.stderr)
        exit_container(container)
        client.close()
        return def_ret

    ##Which patches are in there
    command = "/bin/sh -c 'quilt series'"
    exec_log = client.api.exec_create(container.id,
                                      command, workdir=f"/usr/src/app/{directory}")
    output = client.api.exec_start(exec_log['Id'])

    ##Check if ls is empty
    if "No such file or directory" in str(output):
        exit_container(container)
        client.close()
        return def_ret
    patches = output.splitlines()

    cve_patches = []
    filenames = []
    patch_contents = []
    #Get list and cat all files to find CVE-NNNN-NNNNN pattern in a loop
    for patch in patches:
        if patch != b'.' and patch != b'..' and b'series' not in patch:
            patch_encoded = patch.decode('utf-8')
            command = f"cat {patch_encoded}"
            exec_log = client.api.exec_create(container.id,
                                      command, workdir=f"/usr/src/app/{directory}")
            output = client.api.exec_start(exec_log['Id'])

            # Search for the CVE pattern
            try:
                found = re.search("(?i)CVE-\d{4}-\d{4,}", output.decode('utf-8'))
                found_filename = re.search("(?i)CVE-\d{4}-\d{4,}", patch_encoded)
            except Exception as e:
                print(f"Searched for CVE pattern and found error: {e}", file=sys.stderr)
                exit_container(container)
                client.close()
                return def_ret


            #Prefer filename cve info
            if found_filename:
                #Keep actual CVE patch names
                patch_contents.append(output)
                cve_patches.append(found_filename.group())
                filenames.append(patch_encoded)
                continue

            if found:
                #Keep actual CVE patch names
                patch_contents.append(output)
                cve_patches.append(found.group())
                filenames.append(patch_encoded)

    # XXX debug
    #print(cve_patches)
    #print(filenames)

    #Copy output_directory to host
    bits, stat = container.get_archive("/usr/src/app/output_directory/")
    os.makedirs(f"{args.output_dir}", exist_ok=True)
    with open(f"{args.output_dir}/{directory}", 'wb') as f:
        for chunk in bits:
            f.write(chunk)

    #Remove container
    exit_container(container)

    if len(cve_patches) > 0:
        pass
    else:
        cve_patches = None

    return cve_patches, filenames, patch_contents

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a list of links and extract .deb files")

    parser.add_argument('--input_file', type=str, required=True, help='Path to the input link file')
    parser.add_argument('--image', type=str, required=True, help='Image name')
    parser.add_argument('--output_dir', default="output", type=str, help='Path of output directory')
    parser.add_argument('--timeout', default = 300, type=int, help='Build Timeout')
    parser.add_argument('--parallels', default=16, type=int, help='Number of parallel workers')

    args = parser.parse_args()


    with open(args.input_file, 'r') as f:
        links = f.read()

    for link_batch in (get_batches(links.split(), 170)):
        with concurrent.futures.ProcessPoolExecutor(max_workers=args.parallels) as executor:
            futures = []
            for link in link_batch:
                print(link)
                futures.append(executor.submit(process_link, link, args))

            # Wait for all futures to complete
            results = []
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

