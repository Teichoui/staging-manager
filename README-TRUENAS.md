# Staging Manager for TrueNAS

This is a small Flask app packaged like a TrueNAS SCALE custom app. It exposes a web UI on port 7474, stores config in `/config`, reads media/staging paths through `/media`, and uses `rclone` inside the container.

It is meant to replace the quick SSH chores from the media setup:

- inspect TV and movie staging folders
- spot staging folders that have no video file
- sync one skipped folder from the seedbox with `rclone`
- delete junk staging folders
- browse configured seedbox TV/movie folders
- summarize Sonarr/Radarr import errors
- apply a recursive POSIX ACL repair through the TrueNAS API

## Files

- `Dockerfile` builds the container image.
- `docker-compose.yaml` runs it locally for testing.
- `truenas-custom-app.example.yaml` is the TrueNAS Custom App YAML template.
- `requirements.txt` lists Python dependencies.

## TrueNAS Custom App Flow

1. Build and publish the image:

   ```bash
   docker build -t YOUR_DOCKERHUB_USER/staging-manager:latest .
   docker push YOUR_DOCKERHUB_USER/staging-manager:latest
   ```

2. Edit `truenas-custom-app.example.yaml`:

   - Replace `YOUR_DOCKERHUB_USER/staging-manager:latest`.
   - Confirm `/mnt/tank/apps/staging-manager` exists for app config.
   - Confirm `/mnt/tank/Media` is the host media dataset.
   - Put `rclone.conf` under `/mnt/tank/apps/rclone`.

3. In TrueNAS SCALE Apps, use Custom App / Install via YAML and paste the edited YAML.

4. Open:

   ```text
   http://TRUENAS-IP:7474
   ```

## App Defaults

- Config path: `/config/config.json`
- First run redirects to `/setup`
- Runs HTTP by default. Set `STAGING_MANAGER_HTTPS=true` if you want the app to serve its own self-signed HTTPS endpoint.
- Set `STAGING_MANAGER_SECURE_COOKIES=true` only when users reach the app over HTTPS.
- Set `STAGING_MANAGER_TRUST_PROXY=true` only when the app is behind a trusted reverse proxy that overwrites `X-Forwarded-For`.
- Staging TV path: `/media/staging/tv-sonarr`
- Staging movies path: `/media/staging/radarr`
- Sonarr URL: `http://host.docker.internal:30113`
- Radarr URL: `http://host.docker.internal:30025`
- TrueNAS API URL: `http://host.docker.internal`
- TrueNAS ACL paths: `/mnt/tank/Media/TV`, `/mnt/tank/Media/Movies`, `/mnt/tank/Media/staging`
- TrueNAS Apps UID/GID: `568` / `568`
- rclone excludes: `**/*.rar`, `**/*.r[0-9][0-9]`
- TLS certificate verification for Sonarr/Radarr/TrueNAS API calls is off by default for LAN/self-signed setups. Enable it in Settings if those endpoints have trusted certificates.

If TrueNAS cannot resolve `host.docker.internal`, set the TrueNAS URL in Settings to the NAS LAN IP instead.

## First Run

Open the app and create the admin account on `/setup`. Then open Settings and add:

- Sonarr API key
- Radarr API key
- TrueNAS API key
- rclone remote name and seedbox paths
- rclone excludes and transfer count if you want to change the default RAR skip behavior
- Apps UID/GID if your TrueNAS app user differs from `568`

The app stores these values in `/config/config.json`, which is kept outside the image.
