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
Columns are SHOW	episode	title	DATE	SORTABLE DATE	CHANNEL	DURATION	SIZE (GB)	BITRATE (Mbps)	watchedTime	isNew

Note kmttg's SHOW is has been split back up into  SHOW(show name) ,episode(number) and title (episode name)
The watchedTime(watched seconds into show) and isNew(new vs rerun) columns are not in the kmttg exports.

Planning on direct to google sheet option next.