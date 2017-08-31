# TiVoGet
TiVo metadata downloader based on the kmttg code
It generates csv files similar to kmttg's exports
Usage: TiVoGet TivoName MediaAccessKey TivoIP [OutputDirectory]
TivoName = any name you want
MediaAccessKey = Your TiVo's media access key
TivoIP = Ip address of your TiVo
OutputDirectory = optional path to where you want the files generated.

To-do file is named {TivoName}_Todo.csv
Columns are DATE	SORTABLE DATE	SHOW	CHANNEL	DURATION

OnePass file is named {TivoName}_sp.csv
Columns are PRIORITY	SHOW	INCLUDE	SEASON	CHANNEL	RECORD	KEEP	NUM	START	END

Now Playing List is named {TivoName}_npl.csv
Columns are SHOW	DATE	SORTABLE DATE	CHANNEL	DURATION	SIZE (GB)	BITRATE (Mbps)	watchedTime	isNew

Note the watchedTime and isNew columns are not in the kmttg exports.
