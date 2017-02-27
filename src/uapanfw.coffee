# Description:
#   Manage black/white lists for UA PA FW.
#
# Dependencies:
#   moment
#
# Configuration:
#   xxxxxxxxxxx [required] - API KEY
#
# Commands:
#   hubot fw - fw commands
#
# Notes:
#
# Author:
#   gfjohnson

fs = require 'fs'
moment = require 'moment'

modulename = 'fw'
blacklistfile = modulename + ".json"

try
  fwdata = fs.readFileSync blacklistfile, 'utf-8'
  if fwdata
    data = JSON.parse(fwdata)
catch error
  console.log('Unable to read file', error) unless error.code is 'ENOENT'

module.exports = (robot) ->

  robot.router.get "/#{robot.name}/bl", (req, res) ->
    arr = []
    for obj in data
      arr.push obj.val # XXX: unless expired
    content = '# nothing here yet! #'
    content = arr.join "\n" if arr.length
    res.setHeader 'content-type', 'text/plain'
    res.end content

  robot.respond /fw(?: help)$/, (msg) ->
    cmds = []
    arr = [
      modulename + " blacklist - show blacklist"
      modulename + " blacklist url <url> - add url to blacklist"
      modulename + " blacklist cidr <cidr> - add cidr to blacklist"
    ]

    for str in arr
      cmd = str.split " - "
      cmds.push "`#{cmd[0]}` - #{cmd[1]}"

    robot.send {room: msg.message?.user?.name}, cmds.join "\n"

  robot.respond /fw (?:blacklist|b)$/i, (msg) ->
    logmsg = "#{modulename}: #{msg.envelope.user.name} requested: blacklist"
    robot.logger.info logmsg
    data = fs.readFileSync blacklistfile, 'utf-8'

    robot.send {room: msg.message?.user?.name}, data.join "\n"

  robot.respond /fw (?:blacklist|b) (url|cidr) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    bl =
      created: moment().format()
      expires: moment().add(1, 'months').format()
      type: msg.match[1]
      val: msg.match[2]
    if msg.match.length > 2
      expires = msg.match[3]
      extra = expires.match(/+(\d)([hdwMQy])/)
      if extra?
        n = extra[1]
        unit = extra[2]
        bl.expires = moment().add(n,unit).format()
      else if moment(expires).isValid()
        bl.expires = moment(expires)
      else
        failed = true
        logmsg = "invalid expiration date: #{expires}"
        robot.send {room: msg.message?.user?.name}, logmsg
    
    unless failed
      logmsg = "#{modulename}: #{msg.envelope.user.name} requested: " +
        "blacklist #{bl.type} #{bl.val} expires #{bl.expires}"
      robot.logger.info logmsg
      data.push bl
      fs.writeFileSync blacklistfile, JSON.stringify(data), 'utf-8'
