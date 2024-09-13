# Kubernetes Basics
## Kube API Server
### Central management entity
### Entrypoint for administrative tasks
### REST API
### Receptionist of a large office building. Directs visitors to the appropriate offices
## etcd
### Distributed key value store
### Source of truth for cluster state
### Highly secure and organised filing cabinet where all the cluster documents are stored
## Scheduler
### Responsible for assining pods to nodes
### Considers resource availability, constraints and policies
### Dispatcher for a delivery service. Decides which delivery person gets which package based on location, capacity and workload
## Controller Manager
### Runs controllers as background tasks to handle routine tasks
### Manages replicates and ensures desired state
### Operations manager in a company that oversees multiple departments
## Admission Controllers
### Plugins that govern and enforce how the cluster is configured and used
### Intercept requests to the Kube API Server after AuthN and AuthZ
### Can modify or validate requests
### Like a security guard at a checkpoint. Ensure you comply with specific rules before proceeding
## Ingress
### Kubernetes object that manages external access to services eg HTTP
### Provides routing rules to manage and control traffic
### Like a telephone extension system that routes incoming calls to the right phones based upon predefined rules
## Nodes
### Nodes are worker machines in Kubernetes
### Can be physical or virtual
### Like employees in a company. Has specific roles and reports to a supervisor (kubelet)
## Worker Nodes
### Specifically designated to run application workloads
### Execute the containers and host the pods
### Employees on the factory floor building products
## Service
### An abstraction that defines a logical set of pods and a policy to access them
## Namespace
### Mechanism to divde clusters between multiple users
### Mechanism to scope resources
### Departments in a company that have their own resources and responsibilities
## ConfigMap
### Enable decoupling configuration artifacts from image content to keep portable
### Similar to how an application might read from a config file on startup
## DaemonSet
### Ensures that all (or some) nodes run a copy of a specific pod.
### When new nodes are added to the cluster, a pod from the DaemonSet is added
### Service technician ensuring every machine in a factory has the necessary tools to perform their job
## Kube Proxy
### Network proxy that runs on each node in the cluster
### Maintains network rules and enables communication between different services
### Traffic cop at a busy intersection directing data packets to their correct destinations
## Kubelet
### Agent that runs on each node in the cluster
### Ensures containers are running in pod according to specifications
### Communicates with the Kube API server
### Caretaker of each node ensuring tasks are carried out as instructed