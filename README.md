# @cosphere/client

# Development

## Setup
To load and install all dependencies run:

```
npm install
```

## Workflow
To work with `Client` with live reload run:
```
npm run watch
```

If any error occurs on `gulp watch` task then run
```
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
```
(source: https://stackoverflow.com/questions/16748737/grunt-watch-error-waiting-fatal-error-watch-enospc)

## Documentation
To generate documentation run:

```
npm run doc
```
The doc file will be saved in `/documenation` directory. You can also build and serve the doc on `localhost:5550`. To do it run:
```
npm run doc:serve
```
