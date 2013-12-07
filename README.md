CS640-PA3
=========

Created by: Peter Collins (pcollins) & Cory Groom (groom)

#The Mininet Simple Router

##Background

Software Defined Networking (SND) has emerged over the past several years as a compelling new technology for managing networks – primarily in the local area and in data centers.  The crux of SDN is that it provides network administrators with the ability to flexibly control where traffic flows in a switched environment.  This is done by adding a control plane and certain new capabilities for switching in the data plane in layer 2 devices.  This is quite different from standard layer 2 switches.  In SDN, control is typically assumed to be centralized i.e., it runs on a system that is separate from the switches themselves (referred to as the controller).  This offers certain advantages in terms of algorithms that might be used to manage/control the data plane in switches.  The controller communicates with the switches using a specialized protocol.  One protocol that has been standardized for this purpose is called OpenFlow.  The original paper that describes OpenFlow can be found here.  A very nice overview of software defined networks can be found here. 

The Mininet environment was developed to help promote the development of software defined networks in general and OpenFlow in particular.  The original paper that describes Mininet can be found here.  In that paper, Mininet is described as a rapid prototyping environment for software defined networks.  It is similar to a network simulator, but with the advantage that it relies on the user to create test configurations using a language that is used to configure real systems.  It enables a wide variety of network configurations to be tested and evaluated on a single system instead of having to have a bunch of real OpenFlow-enabled switching hardware.  In fact, Mininet is so flexible and convenient, that it can be used for fairly general kinds of experiments such as classroom projects.

##Description

For this assignment you will continue to conduct experiments with the Mininet simulator.   As in the last programming assignment, to run Mininet, you need a virtual machine.  There are many VM’s available from vendors, many of which are free.  Oracle’s VirtualBox is available in the mumble lab.  We also have the Instructional Virtual Lab, which runs on VMware.  You are welcome to conduct you experiments on your personal systems, but for the purpose of the demo, you will need to run in the Instructional Virtual Lab.   To use the Instructional Virtual Lab, you must request it access using the form that can be found here. You simply need to mention that you want the Mininet template, who is on your team and then CSL set up a VM.  Further documentation is located here.   If you are setting up Mininet on your own systems, you can find instructions on how to do so here.

The specific focus of this programming assignment is to write a simple router that uses a static forwarding table.  The project will give you experience with the POX controller, the Address Resolution Protocol (ARP) and the Internet Control Message Protocol (ICMP).
