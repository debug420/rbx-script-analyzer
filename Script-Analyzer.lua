-- Script Analyzer [OPEN SOURCE]
-- Made by CDXX/CEO of Africa#0591

if not syn then print("Exploit not supported") return end

local write = function(a) rconsoleprint("@@WHITE@@") rconsoleprint(a) end
local writei = function(a) rconsoleprint("@@BLUE@@") rconsoleprint("[*]"..a) end
local writew = function(a) rconsoleprint("@@YELLOW@@") rconsoleprint("[*]"..a.."\n") end
local writee = function(a) rconsoleprint("@@RED@@") rconsoleprint(a) end

rconsolename("Script Analyzer")

writee([[

______             _               _______              _                        
/ _____)           (_)       _     (_______)            | |                       
( (____   ____  ____ _ ____ _| |_    _______ ____  _____| |_   _  ___ _____  ____ 
\____ \ / ___)/ ___) |  _ (_   _)  |  ___  |  _ \(____ | | | | |/___) ___ |/ ___)
_____) | (___| |   | | |_| || |_   | |   | | | | / ___ | | |_| |___ | ____| |    
(______/ \____)_|   |_|  __/  \__) |_|   |_|_| |_\_____|\_)__  (___/|_____)_|    
                    |_|                              (____/                  
                        
                    
Made by CDXX/CEO of Africa#0591


]])

-------------------------------------------------------

-- Command Handling

local commands = {}
local function addcmd(aliases, func)
    assert(type(aliases) == "table", "Invalid arg 1 supplied")
    assert(type(func) == "function", "Invalid arg 2 supplied")
    commands[aliases] = func
end

local function handlerequest(request)
    request = request:lower():split(" ")
    for i,v in pairs(commands) do
        if table.find(i, request[1]) then
            pcall(function() 
                v((function()
                    local t = {}
                    for ii,__ in pairs(request) do
                        if ii ~= 1 then table.insert(t, 1, request[ii]) end
                    end
                    return t;
                end)()) 
            end)
            write("\n")
            break;
        end
    end
    rconsoleprint("@@WHITE@@")
    local input = rconsoleinput()
    handlerequest(input)
end

-------------------------------------------------------

-- Add Commands

local analyzers = {
    Http = false,
    Remotes = false,
    Namecalls = false,
    Indexes = false,
    GTSpy = false,
    SynSpy = false,
    DisableHttpReq = false,
    DisableWebhookReq = false
}

addcmd({"commands", "cmds"}, function(args)
    writew([[
 All commands are followed by a second argument. The second argument is always a bool value (true or false).

 disablehttpreq - Blocks http requests. Usefull for analyzing malicious scripts without consequences.
 disablewebhook - Blocks all http requests that involve discord webhooks.
 http - Analyze http requests made by the script. This will also log syn.requests.
 remote - Logs all remotes that are invoked/fired by the script.
 namecall - Logs all namecalls that are invoked by the script.
 index - Logs all indexes that are invoked by the script.
 _gtable - Logs all changes made to the _G table.
 syntable - Logs all changes made to the syn table.
    ]])
end)

addcmd({"disablewebhook"}, function(args)
    if args[1] == "true" then analyzers.DisableWebhookReq = true else analyzers.DisableWebhookReq = false end
    write("Set webhook disabler to "..tostring(analyzers.DisableWebhookReq).."\n\n")
end)

addcmd({"disablehttpreq", "disablehttp"}, function(args)
    if args[1] == "true" then analyzers.DisableHttpReq = true else analyzers.DisableHttpReq = false end
    write("Set http request disabler to "..tostring(analyzers.DisableHttpReq).."\n\n")
end)

addcmd({"http"}, function(args)
    if args[1] == "true" then analyzers.Http = true else analyzers.Http = false end
    write("Set http analyzer to "..tostring(analyzers.Http).."\n\n")
end)

addcmd({"remote"}, function(args)
    if args[1] == "true" then analyzers.Remotes = true else analyzers.Remotes = false end
    write("Set remote analyzer to "..tostring(analyzers.Remotes).."\n\n")
end)

addcmd({"namecall"}, function(args)
    if args[1] == "true" then analyzers.Namecalls = true else analyzers.Namecalls = false end
    write("Set namecall analyzer to "..tostring(analyzers.Namecalls).."\n\n")
end)

addcmd({"index"}, function(args)
    if args[1] == "true" then analyzers.Indexes = true else analyzers.Indexes = false end
    write("Set index analyzer to "..tostring(analyzers.Indexes).."\n\n")
end)

addcmd({"_gtable"}, function(args)
    if args[1] == "true" then analyzers.GTSpy = true else analyzers.GTSpy = false end
    write("Set _G table analyzer to "..tostring(analyzers.GTSpy).."\n\n")
end)

addcmd({"syntable"}, function(args)
    if args[1] == "true" then analyzers.SynSpy = true else analyzers.SynSpy = false end
    write("Set syn table analyzer to "..tostring(analyzers.SynSpy).."\n\n")
end)

-------------------------------------------------------

-- Gang shit below

local gm = getrawmetatable(game)

local oldnamecall = gm.__namecall
local oldindex = gm.__index

-- Game

setreadonly(gm, false)

gm.__index = newcclosure(function(self, k)
    if checkcaller() and analyzers.Indexes then
        writew("Index Spy - "..tostring(k))
        write(tostring(k).." was indexed by "..tostring(self).."\n\n")
    end
    return oldindex(self, k)
end)
gm.__namecall = newcclosure(function(self, ...)
    local m = getnamecallmethod()
    if checkcaller() and analyzers.Namecalls then
        writew("Namecall Spy - "..tostring(m))
        write("Args: "..tostring((...)).."\n\n")
    end
    return oldnamecall(self, ...)
end)

local oldget, oldgetasync
oldget, oldgetasync = hookfunction(game.HttpGet, function(self, url, ...)
    if not analyzers.Http then print("no http") return oldget(self, url, ...) end
    writew("Http Spy - HttpGet")
    write("A http request was sent to "..tostring(url).."\n\n")
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request\n\n") return end
    return oldget(self, url, ...)
end), hookfunction(game.HttpGetAsync, function(self, url, ...)
    if not analyzers.Http then return oldgetasync(self, url, ...) end
    writew("Http Spy - HttpGetAsync")
    write("A http request was sent to "..tostring(url).."\n\n")
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request\n\n") return end
    return oldgetasync(self, url, ...)
end)

setreadonly(gm, true)

--  Syn

setreadonly(syn, false)

setmetatable(syn, {
    __newindex = function(t, i, v)
        if analyzers.SynSpy then
            writew("Syn Spy - "..tostring(i))
            write("A variable was declared in syn table with the name "..tostring(i).." set to "..tostring(v).."\n\n")
        end
    end
})

local oldrequest = syn.request
syn.request = function(t)
    if analyzers.Http then
        writew("Syn Req Spy - "..tostring(t.Method))
        if t.Body then
            write("A "..tostring(t.Method).." request was sent to "..tostring(t.Url).."\n")
            write("Sending the following information: "..t.Body.."\n\n")
        else
            write("A "..tostring(t.Method).." request was sent to "..tostring(t.Url).."\n\n")
        end
    end
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request") return end
    if analyzers.DisableWebhookReq and (string.find(t.Url, "https://discord.com/api/webhooks/") or string.find(t.Url, "https://discordapp.com/api/webhooks/")) then writee("Blocked HTTP Request to discord webhook.\n\n") return; end
    return oldrequest(t)
end

-- G Spy

setmetatable(_G, {
    __index = function(t, k)
        if analyzers.GTSpy then writew("GT Spy - Invalid Index") write("Attempt to index "..k.." with a nil value inside _G\n\n") end return;
    end,
    __newindex = function(t, i, v) 
        if analyzers.GTSpy then writew("GT Spy - New Index") write("New index was declared with the name of "..tostring(i).." and value of "..tostring(v).."\n\n") end rawset(t, i, v)
    end
})

-- Remote Spy
-- Decided to use hookfunction instead of the namecall metatable above

local oldinvoke, oldfire
oldinvoke, oldfire = hookfunction(Instance.new("RemoteFunction").InvokeServer, function(self, ...)
    if analyzers.Remotes then writew("Remote Spy - "..tostring(self:GetFullName())) write("Remote was invoked with args: "..tostring((...)).."\n\n") end
    return oldinvoke(self, ...)
end), hookfunction(Instance.new("RemoteEvent").FireServer, function(self, ...)
    if analyzers.Remotes then writew("Remote Spy - "..tostring(self:GetFullName())) write("Remote was fired with args: "..tostring((...)).."\n\n") end
    return oldfire(self, ...)
end)

-------------------------------------------------------

-- Initialize

writei("Thank you for using Script Analyzer. Type commands to begin.\n")
handlerequest("")
