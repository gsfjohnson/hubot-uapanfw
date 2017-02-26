# hubot-virustotal

Hubot plugin to get url scan reports from virus total

## Installation

Add **hubot-virustotal** to your `package.json` file:

```javascript
"dependencies": {
  "hubot": ">= 2.5.1",
  "hubot-virustotal": "*"
}
```

Add **hubot-virustotal** to your `external-scripts.json`:

```javascript
["hubot-virustotal"]
```

Run `npm install`

## Usage

Assuming your hubot instance is called `hubot`, you can instruct it to relay a message as follows:

`hubot: virustotal <url>`

Virustotal will be queried and when available the results will be provided to the requestor.


## Configuration

It is necessary to procure an api key from virustotal.com. Once obtained, set this via `HUBOT_VIRUSTOTAL_API` environment variable.

