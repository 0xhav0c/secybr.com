---
title: Recon-ng Tutorials for Enumeration Targets
categories: [red team, reconing]
tags: [recon-ng, recon-ng tutorials, recon-ng best practicies, recon-ng enumeration, recon-ng usage, red-team]
comments: true
---

# Recon-ng Basics

Firstly we need to create a workspaces related to the target organization. It will gather our research and findings under these workspaces.

```shell
workspaces list
workspaces create example-name
```

![Untitled](/assets/img/pitcures/red-team/recon-ng.png)

You can create and list companies.

```shell
db insert companies
show companies
```

![Untitled](/assets/img/pitcures/red-team/recon-ng1.png)

You can add a domain name and list it.

```shell
db insert domains
show domains
```

![Untitled](/assets/img/pitcures/red-team/recon-ng2.png)

## API KEYS

You can find the Recon-ng API Key source [here](https://github.com/Raikia/Recon-NG-API-Key-Creation/blob/master/README-v4.8.3.md).

You can list keys, and add keys.

```shell
keys list #list the keys
keys add example_api xxxxxxxxxxxxxxxxxxxxx # adding API key to module.
keys add binaryedge_api b8880xxxxxxxxxxxxxxxxx # example add api key
```

![Untitled](/assets/img/pitcures/red-team/recon-ng3.png)

## Modules

You can see the modules that can be installed on recon-ng with the marketplace command.

```shell
marketplace search
```

![Untitled](/assets/img/pitcures/red-team/recon-ng4.png)

Modülleri yüklemek için aşağıdaki komutları kullanabilirsiniz

```shell
# To load all modules
marketplace install all # This command will load all supported or unsupported modules doe, but you may get some errors about censys libraries due to some incompatibilities with python 3.10.
# To load modules one by one
marketplace install path # So like this marketplace install recon/companies-contacts/bing_linkedin_cache 

#Note: You may get an error because you did not add the APIs. Not all modules need API. But when adding the modules you need to the API, if the required API value is not available, you will get an error.
```

You can list installed modules.

```shell
modules search
```

![Untitled](/assets/img/pitcures/red-team/recon-ng5.png)

# Start Recon to Targets

We can select the module we want to run and start the recon as follows.

```shell
modules load recon/hosts-ports/censys_ip
options set SOURCE example.com
options set VIRTUAL_HOSTS EXCLUDE # You have three option about this settings = EXCLUDE, INCLUDE, ONLY
run
```

![Untitled](/assets/img/pitcures/red-team/recon-ng6.png)

![Untitled](/assets/img/pitcures/red-team/recon-ng7.png)

We can get reports with the help of the following commands in the workspaces where we have completed our tasks.

```shell
modules search reporting* # You can search modules with '*'. There is some different reporting methods.
modules load reporting/html
info
options set FILENAME /home/user/Desktop/results.html
options set CUSTOMER Company Name
options set CREATOR 0xhav0c
run
```

![Untitled](/assets/img/pitcures/red-team/recon-ng8.png)

![Untitled](/assets/img/pitcures/red-team/recon-ng9.png)

![Untitled](/assets/img/pitcures/red-team/recon-ng10.png)