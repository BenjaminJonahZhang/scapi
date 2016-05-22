############################################################
# Dockerfile to build Scapi Container Images
# Based on Ubuntu 14.04
############################################################

# Set the base image to Ubuntu
FROM ubuntu:14.04

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

# Update the repository sources list
RUN sudo apt-get update -y

# Install prerequisites
RUN sudo apt-get install git -y
RUN sudo apt-get install default-jre -y
RUN sudo apt-get install default-jdk -y
RUN sudo apt-get install build-essential -y
RUN sudo apt-get install ant -y
RUN sudo apt-get install junit4 -y

# Download Scapi from github
RUN cd ~ && git clone https://github.com/cryptobiu/scapi.git

#WORKDIR "/root/scapi/"

RUN cd ~/scapi && git submodule init
RUN cd ~/scapi && git submodule update
RUN cd ~/scapi && sudo make prefix=/usr

# Install Scapi
RUN cd ~/scapi && sudo make install prefix=/usr
