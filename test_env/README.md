

## Topology

```
  +------------------------+  +------------------------+  +------------------------+    +---------------------+
  |                        |  |                        |  |                        |    |                     |
  | VM1                    |  | VM2                    |  | VM3                    |    | VM4                 |
  | Role: Local Router     |  | Role: MEC              |  | Role: Central DC       |    | Role: Router        |
  | MAC: 52:54:00:01:00:01 |  | MAC: 52:54:00:02:00:01 |  | MAC: 52:54:00:03:00:01 |    | SLG01-if:           |
  | IP:  192.168.42.253    |  | IP:  192.168.1.50      |  | IP:  192.168.3.50      |    |   172.16.1.254      |
  |                        |  |                        |  |                        |    |   52:54:00:00:01:01 |
  +-------+----------------+  +-------+----------------+  +-------+----------------+    | SLG02-if:           |
          |                           |                           |                     |   172.16.2.254      |
          |         +-------------------------------------------------------------------+   52:54:00:00:01:02 |
          |         |                 |                           |                     | SLG03-if:           |
          |         |                 |        +----------------------------------------+   172.16.3.254      |
          |         |                 |        |                  |                     |   52:54:00:00:01:03 |
          |         |                 |        |                  |       +-------------+                     |
          |         |                 |        |                  |       |             +---------------------+
          |         |                 |        |                  |       |
+------------------------------------------------------------------------------------+
|         |         |                 |        |                  |       |          |
| +-------+---------+------+  +-------+--------+-------+  +-------+-------+--------+ |
| |                        |  |                        |  |                        | |
| | OF-Bridge01            |  | OF-Bridge02            |  | OF-Bridge03            | |
| | Role: SLG1             |  | Role: SLG2             |  | Role: SLG3             | |
| | Downlink:              |  | Downlink:              |  | Downlink:              | |
| |   192.168.42.254       |  |   192.168.1.254        |  |   192.168.3.254        | |
| |   52:54:00:01:01:01    |  |   52:54:00:02:01:01    |  |   52:54:00:03:01:01    | |
| | Uplink:                |  | Uplink:                |  | Uplink:                | |
| |   172.16.1.1           |  |   172.16.2.1           |  |   172.16.3.1           | |
| |   52:54:00:00:00:01    |  |   52:54:00:00:00:02    |  |   52:54:00:00:00:03    | |
| |                        |  |                        |  |                        | |
| +------------------------+  +------------------------+  +------------------------+ |
|                                                                                    |
+------------------------------------------------------------------------------------+
  Lagopus Switch

```


## Setup

### Install Lagopus

See https://github.com/lagopus/lagopus/blob/master/QUICKSTART.md


### Install Ryu with tunnel extention

```
git clone https://github.com/lagopus/ryu-lagopus-ext
cd ryu-lagopus-ext
git checkout lagopus-general-tunnel-ext
sudo python ./setup.py install
```

### Run Lagopus and Ryu

```
cd ryu_slg/test_env/
./run_lagopus.sh
```

```
cd ryu_slg/test_env/
./run_ryu.sh
```


### Create VMs

install package

```
sudo apt install uvtool
uvt-simplestreams-libvirt sync release=bionic arch=amd64
```

Create VMs

```
cd ryu_slg/test_env
sudo uvt-kvm create vm1 release=bionic --template ./libvirt_templates/VMs/vm1.xml --cpu 2 --memory 2048
sudo uvt-kvm create vm2 release=bionic --template ./libvirt_templates/VMs/vm2.xml --cpu 2 --memory 2048
sudo uvt-kvm create vm3 release=bionic --template ./libvirt_templates/VMs/vm3.xml --cpu 2 --memory 2048
sudo uvt-kvm create vm4 release=bionic --template ./libvirt_templates/VMs/vm3.xml --cpu 2 --memory 2048
```

edit xml

```
virsh edit vm1
virsh edit vm2
virsh edit vm3
virsh edit vm4
```

```
  <cpu mode='host-model'>
    <model fallback='allow'/>
    <topology sockets='1' cores='2' threads='1'/>
+    <numa>
+      <cell id='0' cpus='0-1' memory='2097152' unit='KiB' memAccess='shared'/>
+    </numa>
  </cpu>

```

Restart VMs

```
uvt-kvm ssh vm1 sudo poweroff
uvt-kvm ssh vm2 sudo poweroff
uvt-kvm ssh vm3 sudo poweroff
uvt-kvm ssh vm4 sudo poweroff
```

```
virsh start vm1
virsh start vm2
virsh start vm3
virsh start vm4
```


### (Option) Setup proxy

Edit script

```
vi setup_proxy.sh
```

setup proxy

```
./setup_proxy.sh vm1 vm2 vm3 vm4
```

### Access VMs

```
uvt-kvm ssh vm1
```


