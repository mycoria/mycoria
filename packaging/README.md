# Packaging

# Linux System Service

Run Mycoria as a Linux systemd service:

    cp packaging/mycoria.server /etc/systemd/system/mycoria.service
    systemctl enable mycoria
    systemctl start mycoria
    journalctl -fu mycoria
