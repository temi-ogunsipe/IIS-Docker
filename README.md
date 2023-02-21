# IIS-Docker
For a Windows Server container to use Active Directory authentication, a Group Managed Service Account (gMSA) must be installed on each server that will be hosting the container. The container’s application must then be configured to run as a Network Service. The last step is to use a Credential File in the docker run command to link the container’s Network Service account to a gMSA on the host.
#The base image: this contains iis

docker pull mcr.microsoft.com/dotnet/framework/aspnet:4.8

#Pass-through Authentication
In the original application, the Domain Users security group was granted Read-Only NTFS permissions to the website files to enable pass-through authentication. Unfortunately, this permission can’t be applied to a container image using a Dockerfile. The domain trust relationship with the container is only created after the container is started with –security-opt (more on that below in the Credential Spec File section). So the docker build process can’t look-up domain security groups. Consequently, domain NTFS permissions can only be applied by making the change to a (running) container and then saving the container as a new image. As this would add a manual step to an automated build process, I looked for an alternative.

Instead of using NTFS permissions on the website files, pass-through authentication can also be enabled using the website’s web.config file. In this option, the code (below) is included in the web.config file, which is copied into the container image, along with the other website files, during the docker build process.

<system.web>
  <authentication mode="Windows" />
  <authorization>
    <deny users="?" />
    <allow roles="YOUR_DOMAIN_NAME\Domain Users" />
  </authorization>
</system.web>

#Group Managed Service Account (gMSA)
Each server that can host the container will need to have the application’s gMSA installed on it. A person with Domain Admin (or delegated) permissions will need to create the gMSA account in Active Directory before it can be installed on the hosts. Because there can be multiple hosts in the cluster that is running the container, it’s recommended to create an AD Security Group (that contains all of the host server accounts) and add that security group to the PrincipalsAllowedToRetrieveManagedPassword parameter of the NewADServiceAccount command for the gMSA. That way new container hosts can be added to the security group, instead of having to modify/recreate the gMSA object.

Also, for Windows Server 2016, the gMSA’s (short) name will need to match the hostname parameter used in the docker run command. With Windows Server 2019 and newer, the gMSA name will be used regardless of what hostname is specified.

#Steps for creating gmsa

Add-WindowsFeature RSAT-AD-Powershell;
Import-Module ActiveDirectory; 

# Create the security group 
New-ADGroup -Name "BigFive Hosts" -SamAccountName "BigFiveHosts" -GroupScope DomainLocal -GroupCategory Security -Path "OU=Groups,DC=testdomain,DC=edu"

# Create the gMSA
New-ADServiceAccount -Name "BigFive" -DnsHostName "dockertest1.testdomain.edu" -ServicePrincipalNames "host/dockertest1", "host/dockertest1.testdomain.edu" -PrincipalsAllowedToRetrieveManagedPassword "BigFiveHosts" -Enabled $true;

# Add container hosts to the security group
Add-ADGroupMember -Identity "BigFiveHosts" -Members "dockertest1$,dockertest2$,dockertest3$";

# Install the gMSA on each host server.
Install-ADServiceAccount -Identity BigFive;
Test-ADServiceAccount -Identity BigFive ;

Credential Spec File
As previously stated, the Credential Spec File is what connects the container’s Network Service account to the gMSA. The file is a JSON document that contains metadata (but not any passwords) about the gMSA that is to be used with the container. (The container host retrieves the gMSA on behalf of the container.) For containers that run on multiple hosts, the credential file is created on one host and then copied to the others. To create the credential spec file from an Administrator PowerShell session: install the CredentialSpec module and then use the New-CredentialSpec command. By default the file will be created in the C:\ProgramData\Docker\CredentialSpecs folder.

Install-Module CredentialSpec;
New-CredentialSpec -AccountName BigFive

#Dockerfile
The docker build command docker build -f bigfive.dockerfile -t bigfive . uses a dockerfile named bigfive.dockerfile (code at below) to modify the original ASP.NET image and save the result as a new image named bigfive.

The changes to the ASP.NET image include:

Using icacls to update the NTFS permissions on the wwwroot folder.
Copying the website files from the App folder on the host into the wwwroot.
Enabling IIS Remote Management and creating an IISAdmin login. (For static websites that have separate test/dev environments this might not be necessary)
Adding & enabling the Basic and Windows Authentication features.
Disabling Anonymous Authentication.
Creating a new web application within the Default Web Site. An alternative to this would have been to make the new web application be the default web site. However, since this container will be hosting only 1 web app, changing the default web site was deemed to be unnecessary.
Enable Directory Browsing.
Configure the Default AppPool identity to be ApplicationPoolIdentity, which will allow the IIS service to run using the Network Service account (ie. the Group Managed Service Account).
# escape=`
# parser directive to change default escape character from \ to `

# Windows Server ASP.NET 4.8 image
FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8

LABEL Maintainer="IT"
LABEL version="1.0"
LABEL description="ASP.NET build"

# Update permissions on website folder
RUN icacls 'c:\inetpub\wwwroot' /Grant 'IUSR:(OI)(CI)(RX)'
RUN icacls 'c:\inetpub\wwwroot' /Grant 'IIS AppPool\DefaultAppPool:(OI)(CI)(RX)'

# Copy website files from App host folder to container wwwroot folder
COPY App "c:/inetpub/wwwroot/"

SHELL [ "powershell" ]

# Setup Remote IIS management
RUN Install-WindowsFeature Web-Mgmt-Service; `
New-ItemProperty -Path HKLM:\software\microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1 -Force; `
Set-Service -Name wmsvc -StartupType automatic;

# Add user for Remote IIS Manager Login
RUN net user iisadmin '<Ch@nge This P@ssw0rd>' /ADD /Y; `
net localgroup administrators iisadmin /add;

# Add basic authentication
RUN Install-WindowsFeature Web-Basic-Auth;

# Add Windows authentication
RUN Install-WindowsFeature Web-Windows-Auth;

# Create new web site
RUN New-WebApplication -Name BigFive -Site 'Default Web Site' -PhysicalPath c:\inetpub\wwwroot -ApplicationPool DefaultAppPool;

# Restart web service after enabling basic authentication and creating web application
RUN Restart-Service W3SVC;

# Enable Directory browsing
RUN C:\Windows\system32\inetsrv\appcmd.exe set config 'Default Web Site' /section:system.webServer/directoryBrowse /enabled:'True'

# Disable anonymous authentication
RUN Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -Location 'Default Web Site' -Name enabled -Value False;

# Enable basic authentication
RUN Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/basicAuthentication' -Location 'Default Web Site' -Name enabled -Value True;

# Enable Windows authentication
RUN Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Location 'Default Web Site' -Name Enabled -Value True;

# Run an IIS app pool as Network Service (gMSA)
RUN C:\Windows\system32\inetsrv\appcmd.exe set AppPool DefaultAppPool /processModel.identityType:ApplicationPoolIdentity

# Restart web service
RUN Restart-Service W3SVC;
Starting the new container
Deploying a new container (based on the new image) uses a few parameters to get everything to connect properly. The docker run parameters are:

–p <host port>:<container port>
A port on the host must be mapped to port 80 (or 443) in the container for the host to send web traffic to the correct container. Each host port can only be mapped to a single running container.
If Remote IIS Management has been enabled, then an additional host port will need to be mapped to the container’s port 8172.
–security-opt “credentialspec=file://filename.json”
The security-opt parameter (requires 2 dashes) is used to specify which Credential Spec file will be used by the container.
–hostname
The hostname parameter also requires 2 dashes. As mentioned above, the hostname must match the gMSA name for Windows Server 2016 containers.
-d
The detached (d) parameter is used to run the container as a service, instead of as an interactive process. This allows the container to continue running after the PowerShell window (session) is closed.
–name
The (optional) name parameter can be used to make referencing the container in docker commands easier (as opposed to using the container ID).
docker run  --name bigfive -p 80:80 -p 8172:8172 --security-opt "credentialspec=file://testdomain_bigfive.json" --hostname BigFive -d bigfive
