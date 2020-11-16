# TiVoGet
## **Note this will not work after 12/18/2020 due to certificate issues. The [kmttg project](https://sourceforge.net/projects/kmttg/) which a lot of this is based is being orphaned at that time as well so this will be here only for reference going forward.**

Getting to work with a new keystore should not be that diff but given TiVo's other recent issues (dropped features, preroll ads, random crashes...) I'm giving up on them and will not be putting in the time myself or renewing my TiVo subscriptions.

## Project info
TiVo metadata downloader based on the [kmttg code](https://sourceforge.net/projects/kmttg/)

It generates csv files similar to [kmttg](https://sourceforge.net/projects/kmttg/)'s exports for autmated imports into spreadsheets or DBs.

**Usage: TiVoGet TivoName MediaAccessKey TivoIP [OutputDirectory]**

TivoName = any name you want

MediaAccessKey = Your TiVo's media access key

TivoIP = Ip address of your TiVo

OutputDirectory = optional path to where you want the files generated.

### To-do file is named {TivoName}_Todo.csv

Columns are DATE	SORTABLE DATE	SHOW	CHANNEL	DURATION

### OnePass file is named {TivoName}_sp.csv

Columns are PRIORITY	SHOW	INCLUDE	SEASON	CHANNEL	RECORD	KEEP	NUM	START	END

### Now Playing List is named {TivoName}_npl.csv

Columns are SHOW	episode	title	DATE	SORTABLE DATE	CHANNEL	DURATION	SIZE (GB)	BITRATE (Mbps)	watchedTime	isNew

**Note kmttg's SHOW is has been split back up into  SHOW(show name) ,episode(number) and title (episode name)
The watchedTime(watched seconds into show) and isNew(new vs rerun) columns are not in the kmttg exports.**

