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
displayfmt = '%-4s %-50s %-15s %s'
svcQueueIntervalMs = 300 * 1000

robotRef = false

isAuthorized = (msg) ->
  console.error 'bad robotRef' unless robotRef
  u = msg.envelope.user
  return true if robotRef.auth.hasRole(u,'fw')
  msg.reply "Not authorized.  Missing fw role."
  return false

is2fa = (msg) ->
  console.error 'bad robotRef' unless robotRef
  u = msg.envelope.user
  return true if robotRef.auth.is2fa(u)
  msg.reply "2fa required.  Use `auth 2fa` to validate identity."
  return false

expirationWorker = ->
  bl = fwdata.blacklist
  removequeue = []
  deleted = [
    sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator'
  ]
  for obj in fwdata.blacklist when moment(obj.expires).isAfter()
    deleted.push sprintf displayfmt, obj.type, obj.val, expires.fromNow(),
      obj.creator
    removequeue.push obj

  while removequeue.length > 0
    obj = removequeue.shift()
    bl.splice(bl.indexOf(obj), 1)

  msg = "fw: blacklist entries expired and have been removed. " +
    "Change will be applied in < 5 minutes. Removed: " +
    "```"+ deleted.join("\n") + "```"
  notifySubscribers msg

  fs.writeFileSync blacklistfile, JSON.stringify(fwdata), 'utf-8'

  setTimeout expirationWorker, svcQueueIntervalMs

notifySubscribers = (msg, current_un = false) ->
  console.error 'bad robotRef' unless robotRef
  for un in fwdata.notify
    robotRef.send { room: un }, msg unless current_un && un == current_un


module.exports = (robot) ->

  robotRef = robot
  setTimeout expirationWorker, svcQueueIntervalMs

  fwdata =
    notify: []
    blacklist: []
  try
    fwdata = JSON.parse fs.readFileSync blacklistfile, 'utf-8'
    if Array.isArray(fwdata)
      fwdata =
        notify: []
        blacklist: fwdata
    #robot.logger.info "#{modulename} data loaded"
  catch error
    console.log('Unable to read file', error) unless error.code is 'ENOENT'

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/url", (req, res) ->
    clientip = req.connection.remoteAddress || req.socket.remoteAddress ||
      req.connection.socket.remoteAddress
    logmsg = "#{modulename}: web request from #{clientip}: get url blacklist"
    robot.logger.info logmsg

    arr = []
    for obj in fwdata.blacklist
      if obj.type == 'url' and moment(obj.expires).isAfter()
        arr.push obj.val
    content = '# nothing here yet! #'
    content = arr.join "\n" if arr.length
    res.setHeader 'content-type', 'text/plain'
    res.end content

    logmsg = "#{modulename}: robot responded to web request: sent url blacklist"
    robot.logger.info logmsg

    return

  robot.router.get "/#{robot.name}/#{modulename}/blacklist/cidr", (req, res) ->
    clientip = req.connection.remoteAddress || req.socket.remoteAddress ||
      req.connection.socket.remoteAddress
    logmsg = "#{modulename}: web request from #{clientip}: get cidr blacklist"
    robot.logger.info logmsg

    arr = []
    for obj in fwdata.blacklist
      if obj.type == 'cidr' and moment(obj.expires).isAfter()
        arr.push obj.val
    content = '# nothing here yet! #'
    content = arr.join "\n" if arr.length
    res.setHeader 'content-type', 'text/plain'
    res.end content

    logmsg = "#{modulename}: robot responded to web request: " +
      "sent cidr blacklist"
    robot.logger.info logmsg

    return

  robot.respond /fw(?: help| h|)$/, (msg) ->
    cmds = ['```']
    arr = [
      modulename + " blacklist [(cidr|url) [searchterm]] - show blacklist"
      modulename + " blacklist add (url|cidr) <weburl.tld/etc|x.x.x.x> - add to blacklist"
      modulename + " blacklist del (url|cidr) <weburl.tld/etc|x.x.x.x> - del from blacklist"
      modulename + " blacklist notify [username] - notify when changes happen"
      modulename + " blacklist subscribers - list notify subscribers"
    ]

    for str in arr
      #cmd = str.split " - "
      #cmds.push "#{cmd[0]} - #{cmd[1]}"
      cmds.push str
    cmds.push '```'

    msg.reply cmds.join "\n"

    logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
      "displayed #{modulename} help"
    robot.logger.info logmsg

    return

  robot.respond /fw (?:blacklist|b)(?: (cidr|url)(?: ([^ ]+)|)|)$/i, (msg) ->
    logmsg = "#{modulename}: #{msg.envelope.user.name} requested: show blacklist"
    robot.logger.info logmsg

    bl_type = false
    bl_type = msg.match[1] if msg.match[1]

    bl_search = false
    bl_search = msg.match[2] if msg.match[2]

    arr = []
    arr.push sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator'
    for obj in fwdata.blacklist
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
      arr.push sprintf displayfmt, obj.type, obj.val, expires.fromNow(), obj.creator

    msg.reply "Blacklist items and expirations\n```\n"+ arr.join("\n") + "\n```"

    logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
      "displayed blacklist items and expirations"
    robot.logger.info logmsg

    return

  robot.respond /fw (?:blacklist|b) add (url|cidr) ([^ ]+)(?: ([^ ]+)|)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    who = msg.envelope.user.name

    bl =
      created: moment().format()
      expires: moment().add(1, 'months').format()
      type: String(msg.match[1])
      val: String(msg.match[2])
      creator: who

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
        usermsg = "invalid expiration date: #{expires}"
        return msg.reply usermsg
    
    logmsg = "#{modulename}: #{who} requested: " +
      "blacklist #{bl.type} #{bl.val} expires #{bl.expires}"
    robot.logger.info logmsg

    fwdata.blacklist.push bl
    fs.writeFileSync blacklistfile, JSON.stringify(fwdata), 'utf-8'

    usermsg = "#{who} added `#{bl.val}` to firewall blacklist. " +
      "Expires `#{bl.expires}`.  Change will be applied in < 5 minutes."
    msg.reply usermsg

    logmsg = "#{modulename}: robot responded to #{who}: " +
      "added entry to blacklist"
    robot.logger.info logmsg

    #usermsg = usermsg.replace(/  Change will be applied in \< 5 minutes\./, '')
    notifySubscribers usermsg, who

    return

  robot.respond /fw (?:blacklist|b) (?:delete|del|d) (url|cidr) ([^ ]+)$/i, (msg) ->
    return unless isAuthorized msg
    return unless is2fa msg

    who = msg.envelope.user.name
    bl_type = String(msg.match[1])
    bl_search = String(msg.match[2])

    if bl_search.toLowerCase().indexOf('https://') == 0
      usermsg = "Blacklisting of https links not supported."
      return msg.reply usermsg

    if bl_search.toLowerCase().indexOf('http') == 0
      bl_search = bl_search.replace(/http:\/\//i,'')

    logmsg = "#{modulename}: #{who} requested: " +
      "blacklist delete #{bl_type} #{bl_search}"
    robot.logger.info logmsg

    deleted = []
    new_bl = []
    deleted.push sprintf displayfmt, 'Type', 'Value', 'Expiration', 'Creator'
    for obj in fwdata.blacklist
      expires = moment(obj.expires)
      if bl_type and bl_type != obj.type
        errfmt = 'type: [%s] != [%s]'
        #console.log sprintf errfmt, bl_type, obj.type
        new_bl.push obj
        continue
      if bl_search and obj.val.indexOf(bl_search) == -1
        errfmt = 'search: indexOf[%s] not found in [%s]'
        #console.log sprintf errfmt, bl_search, obj.val
        new_bl.push obj
        continue
      if expires.isBefore() # now
        #console.log 'expires: ['+ expires +'] is before now'
        new_bl.push obj
        continue
      deleted.push sprintf displayfmt, obj.type, obj.val,
        expires.fromNow(), obj.creator

    deltaN = fwdata.blacklist.length - new_bl.length
    if deltaN > 0
      usermsg = "#{who} removed `#{deltaN}` fw blacklist entries.  " +
        "Change will be applied in < 5 minutes. Removed: " +
        "```"+ deleted.join("\n") + "```"
      fwdata.blacklist = new_bl
      fs.writeFileSync blacklistfile, JSON.stringify(fwdata), 'utf-8'
    else
      usermsg = "Blacklist delete request did not match any records."
    msg.reply usermsg

    logmsg = "#{modulename}: robot responded to #{msg.envelope.user.name}: " +
      "removed #{deltaN} entries from blacklist"
    robot.logger.info logmsg

    if deltaN > 0
      #usermsg = usermsg.replace(/  Change will be applied in \< 5 minutes\./, '')
      notifySubscribers usermsg, who

    return

  robot.respond /fw (?:blacklist|b) (?:notify|n)(?: ([^ ]+))$/i, (msg) ->
    user = msg.envelope.user
    who = user.name
    who = msg.match[1] if msg.match[1]

    logmsg = "#{modulename}: #{user.name} requested: notify #{who}"
    robot.logger.info logmsg

    fwdata.notify.push who unless who in fwdata.notify

    usermsg = "Added `#{who}` to firewall blacklist notifications."
    msg.reply usermsg

    logmsg = "#{modulename}: robot responded to #{user.name}: " +
      "added #{who} to blacklist notifications"
    robot.logger.info logmsg

    fs.writeFileSync blacklistfile, JSON.stringify(fwdata), 'utf-8'

    return

  robot.respond /fw (?:blacklist|b) (?:subscribers|s)$/i, (msg) ->
    who = msg.envelope.user.name

    logmsg = "#{modulename}: #{who} requested: subscribers"
    robot.logger.info logmsg

    usermsg = "Subscriber list: `"+ fwdata.notify.join('`, `') + "`"
    msg.reply usermsg

    logmsg = "#{modulename}: robot responded to #{who}: " +
      fwdata.notify.join(', ')
    robot.logger.info logmsg

    return

  robot.respond /fw (?:blacklist|b) (?:unnotify|un)(?: ([^ ]+))$/i, (msg) ->
    user = msg.envelope.user
    who = msg.envelope.user.name
    who = msg.match[1] if msg.match[1]

    logmsg = "#{modulename}: #{user.name} requested: unnotify #{who}"
    robot.logger.info logmsg

    n = fwdata.notify.indexOf(who)
    fwdata.notify.splice(n, 1) if n > -1

    usermsg = "Removed `#{who}` from firewall blacklist notifications."
    msg.reply usermsg

    logmsg = "#{modulename}: robot responded to #{user.name}: " +
      "removed #{who} from blacklist notifications"
    robot.logger.info logmsg

    fs.writeFileSync blacklistfile, JSON.stringify(fwdata), 'utf-8'

    return

