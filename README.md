# ubuntu-core-manager

Web-based management daemon (port 7990) for Ubuntu / Ubuntu Core:
- Network Setup (netplan via D-Bus API)
- Snap Install (via snapd socket)
- Interface Connections (via snapd socket)

## Run locally (development)
    npm install
    sudo PORT=7990 npm start
    # open http://localhost:7990

## Build the snap
    snapcraft
    sudo snap install ubuntu-core-manager_1.0.0_amd64.snap --dangerous

## Connect required interfaces
    sudo snap connect ubuntu-core-manager:snapd-control
    sudo snap connect ubuntu-core-manager:network-setup-control
    sudo snap connect ubuntu-core-manager:netplan-dbus

Access the UI at http://localhost:7990
