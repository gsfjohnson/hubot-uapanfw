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
#   requires hubot-auth be present
#
# Author:
#   gfjohnson

fs = require 'fs'
moment = require 'moment'
sprintf = require("sprintf-js").sprintf

modulename = 'fw'
blacklistfile = modulename + ".json"

isAuthorized = (robot, msg) ->
  u = msg.envelope.user
  return true if robot.auth.hasRole(u,'fw')
  msg.reply "Not authorized.  Missing fw role."
  return false

isSudo = (robot, msg) ->
  u = msg.envelope.user
  return true if robot.auth.isSudo(u)
  msg.reply "Sudo required."
  return false

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
    cmds = ['```']
    arr = [
      modulename + " blacklist - show blacklist"
      modulename + " blacklist add (url|cidr) <url|cidr> - add to blacklist"
      modulename + " blacklist del (url|cidr) <url|cidr> - del from blacklist"
    ]

    for str in arr
      cmd = str.split " - "
      cmds.push "#{cmd[0]} - #{cmd[1]}"
    cmds.push '```'

    msg.reply cmds.join "\n"

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

    arr = []
    fmt = '%-4s %-50s %-15s %s'
    arr.push sprintf fmt, 'Type', 'Value', 'Expiration', 'Creator'
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
      arr.push sprintf fmt, obj.type, obj.val, expires.fromNow(), obj.creator

    msg.reply "Blacklist items and expirations\n```\n"+ arr.join("\n") + "\n```"

    logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
      "displayed blacklist items and expirations"
    robot.logger.info logmsg

  robot.respond /fw (?:blacklist|b) add (url|cidr) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unless isAuthorized robot, msg
    return unless isSudo robot, msg

    bl =
      created: moment().format()
      expires: moment().add(1, 'months').format()
      type: msg.match[1]
      val: msg.match[2]
      creator: msg.envelope.user.name

    if bl.val.toLowerCase().indexOf('https://') == 0
      usermsg = "Blacklisting of https links not supported."
      return msg.reply usermsg

    if bl.val.toLowerCase().indexOf('http') == 0
      bl.val = bl.val.replace(/http:\/\//i,'')

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
        usermsg = "invalid expiration date: #{expires}"
        msg.reply usermsg
    
    unless failed
      logmsg = "#{modulename}: #{msg.envelope.user.name} requested: " +
        "blacklist #{bl.type} #{bl.val} expires #{bl.expires}"
      robot.logger.info logmsg

      data.push bl
      fs.writeFileSync blacklistfile, JSON.stringify(data), 'utf-8'

      usermsg = "Added #{bl.val} to firewall blacklist, " +
        "expiring #{bl.expires}.  Change will be applied in < 5 minutes."
      msg.reply usermsg

      logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
        "added entry to blacklist"
      robot.logger.info logmsg

  robot.respond /fw (?:blacklist|b) (?:delete|del|d) (url|cidr) ([^ ]+)$/i, (msg) ->
    return unless isAuthorized robot, msg
    return unless isSudo robot, msg

    bl_type = msg.match[1]
    bl_search = msg.match[2]

    logmsg = "#{modulename}: #{msg.envelope.user.name} requested: " +
      "blacklist delete #{bl_type} #{bl_search}"
    robot.logger.info logmsg

    arr = []
    newdata = []
    fmt = '%-4s %-50s %-15s %s'
    arr.push sprintf fmt, 'Type', 'Value', 'Expiration', 'Creator'
    for obj in data
      expires = moment(obj.expires)
      if bl_type and bl_type != obj.type
        newdata.push obj
        continue
      if bl_search and obj.val.indexOf(bl_search) == -1
        newdata.push obj
        continue
      if expires.isBefore() # now
        newdata.push obj
        continue
      arr.push sprintf fmt, obj.type, obj.val, expires.fromNow(), obj.creator

    # drop deleted records
    deltaN = data.length - newdata.length
    data = newdata
    fs.writeFileSync blacklistfile, JSON.stringify(data), 'utf-8'

    usermsg = "Removed #{deltaN} entries from firewall blacklist.  " +
      "Change will be applied in < 5 minutes.\n" +
      "Removed: ```"+ arr.join("\n") + "```"
    msg.reply usermsg

    logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
      "removed #{deltaN} entries from blacklist"
    robot.logger.info logmsg
