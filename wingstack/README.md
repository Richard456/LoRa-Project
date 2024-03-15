# WingStack LoRa Network Server

## Prerequisites:

The server requires the following packages:
* `requests-futures`
* `pycryptodome`

## Running the server

### Preparation
First, "install" the server package locally: `pip install -e .`

This only needs to be done for the first time and any time new python module
is added to the project.

Then, you'll also need to place the configuration file into one of the default
locations:
* `$HOME/.config/wingstack/server_config.json`
* `/etc/wingstack/server_config.json`

An example configuration file has been provided at `server_config.example.json`.
The configuration that are not in the default location can also be used with
`-c` parameter when launching the program.

### Launching the server
To start the server: `python -m src.lora_server.lora_server`