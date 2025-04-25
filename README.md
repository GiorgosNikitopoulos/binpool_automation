# Binpool Automation 

Binpool Automation is the tool that creates the Binpool Dataset via a list of links referring to Debian Source Control files.

## Description

Binpool Automation works by fetching those debian projects, detecting their security patch backports via their CVE id,
and iteratively popping and compiling (thus popncomp.py) each (vulnerable) version of the project. 
It also creates a non-vulnerable version of the project by abstaining from popping any patch (denoted by None).
The project supports multiple debian compilation environments in the form of docker images thus allowing greater expansion
of compilable projects across debian versions. 

## Usage

### Installing Dependencies
This project is dependent on Docker being installed. To install docker please refer to:
[This Link](https://docs.docker.com/engine/install/)

To install the dependencies required to run our automation create and activate a virtual environment:
```
python3 -m venv venv
source venv/bin/activate
```

then install the requirements by running:
```
python3 -m pip install -r requirements.txt
```

To create a building environment image use the Dockerfile contained within the directory 
(to create the stretch build environment) run from project root:
```
cd stretch
docker build -t stretch .
```

### DSC lists
Use as input to popncomp a dsc list of newline seperated snapshot dsc links.
The provided list is named: `dsc_list.txt`
You can modify this list to your own liking or create one of your own.

### Running popncomp

To run popncomp:
```
usage: popncomp.py [-h] --input_file INPUT_FILE --image IMAGE [--output_dir OUTPUT_DIR] [--timeout TIMEOUT] [--parallels PARALLELS]

Process a list of links and extract .deb files

options:
  -h, --help            show this help message and exit
  --input_file INPUT_FILE
                        Path to the input link file
  --image IMAGE         Image name
  --output_dir OUTPUT_DIR
                        Path of output directory
  --timeout TIMEOUT     Build Timeout
  --parallels PARALLELS
                        Number of parallel workers
```

example:
```
mkdir output_dir
python3 popncomp.py --input_file dsc_list.txt --image stretch
```

## Authors

* [@GiorgosNikitopoulos](https://github.com/GiorgosNikitopoulos)(Corresponding Author of this project)
* [@aaronportnoy](https://github.com/aaronportnoy)
* [@spencerwuwu](https://github.com/spencerwuwu)

## License

This project is licensed under the BSD License - see the LICENSE file for details

## Acknowledgments
Special thanks to [Christophe Hauser](https://faculty-directory.dartmouth.edu/christophe-hauser) and [Sima Arasteh](https://github.com/SimaArasteh)
