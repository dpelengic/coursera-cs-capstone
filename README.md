# Coursera Cybersecurity Capstone project

May, 2018

## About

Application made for the Cybersecurity Capstone project, organized by University of Maryland on the Coursera platform.

## Requirements

The required (versioned) packages are found in requirements.txt.

Also requires a working Nginx service. A sample configuration I used for the contest is found inside this project.
Make sure to request your own Letsencrypt certificate and specify it in the configuration.

## Example usage

Running with virtualenv:

```shell
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

For test runs, I suggest running the application with supervisor, inside a screen instance - for the automatic restarts in case of a crash.

Install superviso (Ubuntu system):

```shell
sudo apt-get install supervisor
```

Example configuration is in the supervisor.conf file.

Invoke the supervisor inside the project folder, like this:

```shell
supervisord
```

