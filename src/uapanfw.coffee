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

module.exports = (robot) ->

  data = []
  try
    fwdata = fs.readFileSync blacklistfile, 'utf-8'
    if fwdata
      data = JSON.parse(fwdata)
      console.log "#{modulename} blacklist loaded: " + data.length + " entries"
  catch error
    console.log('Unable to read file', error) unless error.code is 'ENOENT'

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/url", (req, res) ->
    clientip = req.connection.remoteAddress || req.socket.remoteAddress ||
      req.connection.socket.remoteAddress
    logmsg = "#{modulename}: web request from #{clientip}: url blacklist"
    robot.logger.info logmsg

    arr = []
    for obj in data
      if obj.type == 'url' and moment(obj.expires).isAfter()
        arr.push obj.val
    content = '# nothing here yet! #'
    content = arr.join "\n" if arr.length
    res.setHeader 'content-type', 'text/plain'
    res.end content

    logmsg = "#{modulename}: robot responded to web request: sent url blacklist"
    robot.logger.info logmsg

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/cidr", (req, res) ->
    clientip = req.connection.remoteAddress || req.socket.remoteAddress ||
      req.connection.socket.remoteAddress
    logmsg = "#{modulename}: web request from #{clientip}: cidr blacklist"
    robot.logger.info logmsg

    arr = []
    for obj in data
      if obj.type == 'cidr' and moment(obj.expires).isAfter()
        arr.push obj.val
    content = '# nothing here yet! #'
    content = arr.join "\n" if arr.length
    res.setHeader 'content-type', 'text/plain'
    res.end content

    logmsg = "#{modulename}: robot responded to web request: " +
      "sent cidr blacklist"
    robot.logger.info logmsg

  robot.respond /fw(?: help|)$/, (msg) ->
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

    logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
      "displayed #{modulename} help"
    robot.logger.info logmsg

  robot.respond /fw (?:blacklist|b)(?: (cidr|url)(?: ([^ ]+)|)|)$/i, (msg) ->
    logmsg = "#{modulename}: #{msg.envelope.user.name} requested: blacklist"
    robot.logger.info logmsg

    bl_type = false
    bl_type = msg.match[1] if msg.match[1]

    bl_search = false
    bl_search = msg.match[2] if msg.match[2]

    arr = ['Blacklist items and expirations']
    for obj in data
      expires = moment(obj.expires)
      if bl_type and bl_type != obj.type
        #console.log 'skipping type: '+ obj.type
        continue
      if bl_search and obj.val.indexOf(bl_search) == -1
        #console.log 'skipping search: '+ obj.val
        continue
      if expires.isBefore() # now
        #console.log 'skipping expires: '+ obj.expires
        continue
      #console.log 'adding to array: '
      #console.log obj
      arr.push "#{obj.type} `#{obj.val}` #{expires.fromNow()}"

    msg.reply arr.join "\n"

    logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
      "displayed blacklist items and expirations"
    robot.logger.info logmsg

  robot.respond /fw (?:blacklist|b) (url|cidr) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    bl =
      created: moment().format()
      expires: moment().add(1, 'months').format()
      type: msg.match[1]
      val: msg.match[2]
    if msg.match[3]?
      expires = msg.match[3]
      extra = expires.match /\+(\d)([hdwMQy])/
      if extra?
        n = extra[1]
        unit = extra[2]
        bl.expires = moment().add(n,unit).format()
      else if moment(expires).isValid()
        bl.expires = moment(expires).format()
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

      logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
        "added entry to blacklist"
      robot.logger.info logmsg
