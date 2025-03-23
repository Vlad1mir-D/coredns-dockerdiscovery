package dockerdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	dockerapi "github.com/fsouza/go-dockerclient"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("docker")

type ContainerInfo struct {
	container *dockerapi.Container
	address   net.IP
	address6  net.IP
	domains   []string // resolved domain
}

type ContainerInfoMap map[string]*ContainerInfo

type ContainerDomainResolver interface {
	// Return domains in any format - they will be normalized
	// to canonical FQDN format (lowercase with trailing dot)
	resolve(container *dockerapi.Container) ([]string, error)
}

// DockerDiscovery is a plugin that conforms to the coredns plugin interface
type DockerDiscovery struct {
	Next           plugin.Handler
	dockerEndpoint string
	resolvers      []ContainerDomainResolver
	dockerClient   *dockerapi.Client

	mutex            sync.RWMutex
	containerInfoMap ContainerInfoMap
	ttl              uint32
}

// normalizeDomain ensures consistent domain representation by:
// 1. Converting to lowercase (DNS is case-insensitive)
// 2. Ensuring proper FQDN format with trailing dot
func normalizeDomain(domain string) string {
	// Convert to lowercase for case-insensitive comparison
	domain = strings.ToLower(domain)

	// Ensure domain ends with exactly one trailing dot
	domain = strings.TrimSuffix(domain, ".")
	return domain + "."
}

// NewDockerDiscovery constructs a new DockerDiscovery object
func NewDockerDiscovery(dockerEndpoint string) *DockerDiscovery {
	return &DockerDiscovery{
		dockerEndpoint:   dockerEndpoint,
		containerInfoMap: make(ContainerInfoMap),
		ttl:              3600,
	}
}

func (dd *DockerDiscovery) resolveDomainsByContainer(container *dockerapi.Container) ([]string, error) {
	var domains []string
	for _, resolver := range dd.resolvers {
		d, err := resolver.resolve(container)
		if err != nil {
			log.Warningf("Error resolving container domains %s", err)
		}

		// Normalize each domain from resolver
		for _, domain := range d {
			domains = append(domains, normalizeDomain(domain))
		}
	}

	return domains, nil
}

func (dd *DockerDiscovery) containerInfoByDomain(requestName string) (*ContainerInfo, error) {
	dd.mutex.RLock()
	defer dd.mutex.RUnlock()

	// Normalize the request name
	normalizedRequest := normalizeDomain(requestName)

	for _, containerInfo := range dd.containerInfoMap {
		for _, d := range containerInfo.domains {
			normalizedDomain := normalizeDomain(d)
			if normalizedRequest == normalizedDomain {
				return containerInfo, nil
			}
		}
	}

	return nil, nil
}

// ServeDNS implements plugin.Handler
func (dd *DockerDiscovery) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	var answers []dns.RR
	switch state.QType() {
	case dns.TypeA:
		containerInfo, _ := dd.containerInfoByDomain(state.QName())
		if containerInfo != nil {
			answers = getAnswer(state.Name(), []net.IP{containerInfo.address}, dd.ttl, false)
		}
	case dns.TypeAAAA:
		containerInfo, _ := dd.containerInfoByDomain(state.QName())
		if containerInfo != nil && containerInfo.address6 != nil {
			answers = getAnswer(state.Name(), []net.IP{containerInfo.address6}, dd.ttl, true)
		} else if containerInfo != nil && containerInfo.address != nil {
			// In accordance with RFC 4074 section 3, when only A record exists but AAAA is requested,
			// we should return an empty answer section (NOERROR with 0 answers)
			answers = []dns.RR{} // This creates an empty answer section
		}
	}

	if len(answers) == 0 {
		// Check if it's an AAAA query for a domain that exists with only an A record
		if state.QType() == dns.TypeAAAA {
			containerInfo, _ := dd.containerInfoByDomain(state.QName())
			if containerInfo != nil && containerInfo.address != nil {
				// Domain exists with A record but no AAAA - return NOERROR with empty answer
				m := new(dns.Msg)
				m.SetReply(r)
				m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true

				state.SizeAndDo(m)
				m = state.Scrub(m)
				err := w.WriteMsg(m)
				if err != nil {
					log.Errorf("Error: %s", err.Error())
				}
				return dns.RcodeSuccess, nil
			}
		}
		return plugin.NextOrFailure(dd.Name(), dd.Next, ctx, w, r)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true
	m.Answer = answers

	state.SizeAndDo(m)
	m = state.Scrub(m)
	err := w.WriteMsg(m)
	if err != nil {
		log.Errorf("Error: %s", err.Error())
	}
	return dns.RcodeSuccess, nil
}

// Name implements plugin.Handler
func (dd *DockerDiscovery) Name() string {
	return "docker"
}

func (dd *DockerDiscovery) getContainerAddress(container *dockerapi.Container, v6 bool) (net.IP, error) {

	// save this away
	netName, hasNetName := container.Config.Labels["coredns.dockerdiscovery.network"]

	var networkMode string

	// Debug container networks when a specific network is requested
	if hasNetName {
		dd.debugContainerNetworks(container, netName)
	}

	for {
		if container.NetworkSettings.IPAddress != "" && !hasNetName && !v6 {
			return net.ParseIP(container.NetworkSettings.IPAddress), nil
		}

		if container.NetworkSettings.GlobalIPv6Address != "" && !hasNetName && v6 {
			return net.ParseIP(container.NetworkSettings.GlobalIPv6Address), nil
		}

		networkMode = container.HostConfig.NetworkMode

		// TODO: Deal with containers run with host ip (--net=host)
		if networkMode == "host" {
			log.Infof("Container uses host network")
			return nil, nil
		}

		if strings.HasPrefix(networkMode, "container:") {
			log.Infof("Container %s is in another container's network namespace", container.ID[:12])
			otherID := container.HostConfig.NetworkMode[len("container:"):]
			var err error
			container, err = dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: otherID})
			if err != nil {
				return nil, err
			}
		} else {
			break
		}
	}

	// Check if the container has any networks
	if len(container.NetworkSettings.Networks) == 0 {
		return nil, fmt.Errorf("container %s has no networks", container.ID[:12])
	}

	// If a specific network is specified via label, use that one
	if hasNetName {
		log.Debugf("network name %s specified (%s)", netName, container.ID[:12])

		if network, ok := container.NetworkSettings.Networks[netName]; ok {
			if !v6 {
				return net.ParseIP(network.IPAddress), nil
			} else if v6 && len(network.GlobalIPv6Address) > 0 {
				return net.ParseIP(network.GlobalIPv6Address), nil
			}
			// If we're looking for IPv6 but none exists, return nil
			return nil, nil
		}

		return nil, fmt.Errorf("specified network %s not found for container %s", netName, container.ID[:12])
	}

	// If there's exactly one network, use that
	if len(container.NetworkSettings.Networks) == 1 {
		for _, network := range container.NetworkSettings.Networks {
			if !v6 {
				return net.ParseIP(network.IPAddress), nil
			} else if v6 && len(network.GlobalIPv6Address) > 0 {
				return net.ParseIP(network.GlobalIPv6Address), nil
			}
			// If we're looking for IPv6 but none exists, return nil
			return nil, nil
		}
	}

	// If we get here, the container has multiple networks but no specific one was specified.
	// Try to find a "default" bridge network first
	if network, ok := container.NetworkSettings.Networks["bridge"]; ok {
		if !v6 {
			return net.ParseIP(network.IPAddress), nil
		} else if v6 && len(network.GlobalIPv6Address) > 0 {
			return net.ParseIP(network.GlobalIPv6Address), nil
		}
	}

	// If there's no bridge network, use the first one that has an IP address
	for netName, network := range container.NetworkSettings.Networks {
		if !v6 && network.IPAddress != "" {
			log.Debugf("using network %s for container %s (has multiple networks)", netName, container.ID[:12])
			return net.ParseIP(network.IPAddress), nil
		} else if v6 && len(network.GlobalIPv6Address) > 0 {
			log.Debugf("using network %s for container %s IPv6 (has multiple networks)", netName, container.ID[:12])
			return net.ParseIP(network.GlobalIPv6Address), nil
		}
	}

	// If we get here, no suitable network was found
	return nil, fmt.Errorf("no suitable network found for container %s", container.ID[:12])
}

// debugContainerNetworks prints information about a container's networks for debugging
func (dd *DockerDiscovery) debugContainerNetworks(container *dockerapi.Container, requestedNetwork string) {
	log.Debugf("Container %s (%s) networks:", normalizeContainerName(container), container.ID[:12])
	for netName, network := range container.NetworkSettings.Networks {
		log.Debugf("  - Network: %s, IP: %s, IPv6: %s",
			netName, network.IPAddress, network.GlobalIPv6Address)
	}
	log.Debugf("Requested network: %s", requestedNetwork)
}

func (dd *DockerDiscovery) updateContainerInfo(container *dockerapi.Container) error {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()

	_, isExist := dd.containerInfoMap[container.ID]
	if isExist { // remove previous resolved container info
		delete(dd.containerInfoMap, container.ID)
	}

	containerAddress, err := dd.getContainerAddress(container, false)
	if err != nil || containerAddress == nil {
		log.Infof("Remove container entry %s (%s)", normalizeContainerName(container), container.ID[:12])
		return err
	}

	containerAddress6, err := dd.getContainerAddress(container, true)

	domains, _ := dd.resolveDomainsByContainer(container)
	if len(domains) > 0 {
		dd.containerInfoMap[container.ID] = &ContainerInfo{
			container: container,
			address:   containerAddress,
			address6:  containerAddress6,
			domains:   domains,
		}

		if !isExist {
			log.Infof("Add entry of container %s (%s). IP: %v, FQN: %s", normalizeContainerName(container), container.ID[:12], containerAddress, domains)
		}
	} else if isExist {
		log.Infof("Remove container entry %s (%s)", normalizeContainerName(container), container.ID[:12])
	}
	return nil
}

func (dd *DockerDiscovery) removeContainerInfo(containerID string) error {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()

	containerInfo, ok := dd.containerInfoMap[containerID]
	if !ok {
		log.Debugf("No entry associated with the container %s", containerID[:12])
		return nil
	}
	log.Infof("Deleting entry %s (%s)", normalizeContainerName(containerInfo.container), containerInfo.container.ID[:12])
	delete(dd.containerInfoMap, containerID)

	return nil
}

func (dd *DockerDiscovery) start() error {
	log.Infof("start")
	events := make(chan *dockerapi.APIEvents)

	if err := dd.dockerClient.AddEventListener(events); err != nil {
		return err
	}

	containers, err := dd.dockerClient.ListContainers(dockerapi.ListContainersOptions{})
	if err != nil {
		return err
	}

	for _, apiContainer := range containers {
		container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: apiContainer.ID})
		if err != nil {
			// TODO err
		}
		if err := dd.updateContainerInfo(container); err != nil {
			log.Warningf("Error adding A/AAAA records for container %s: %s", container.ID[:12], err)
		}
	}

	for msg := range events {
		go func(msg *dockerapi.APIEvents) {
			event := fmt.Sprintf("%s:%s", msg.Type, msg.Action)
			switch event {
			case "container:start":
				log.Infof("New container spawned. Attempt to add A/AAAA records for it")

				container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.ID})
				if err != nil {
					log.Warningf("Event error %s #%s: %s", event, msg.Actor.ID[:12], err)
					return
				}
				if err := dd.updateContainerInfo(container); err != nil {
					log.Warningf("Error adding A/AAAA records for container %s: %s", container.ID[:12], err)
				}
			case "container:die":
				log.Infof("Container being stopped. Attempt to remove its A/AAAA records from the DNS %s", msg.Actor.ID[:12])
				if err := dd.removeContainerInfo(msg.Actor.ID); err != nil {
					log.Warningf("Error deleting A/AAAA records for container: %s: %s", msg.Actor.ID[:12], err)
				}
			case "network:connect":
				// take a look https://gist.github.com/josefkarasek/be9bac36921f7bc9a61df23451594fbf for example of same event's types attributes
				log.Infof("Container %s being connected to network %s.", msg.Actor.Attributes["container"][:12], msg.Actor.Attributes["name"])

				container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.Attributes["container"]})
				if err != nil {
					log.Warningf("Event error %s #%s: %s", event, msg.Actor.Attributes["container"][:12], err)
					return
				}
				if err := dd.updateContainerInfo(container); err != nil {
					log.Warningf("Error adding A/AAAA records for container %s: %s", container.ID[:12], err)
				}
			case "network:disconnect":
				log.Infof("Container %s being disconnected from network %s", msg.Actor.Attributes["container"][:12], msg.Actor.Attributes["name"])

				container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.Attributes["container"]})
				if err != nil {
					log.Warningf("Event error %s #%s: %s", event, msg.Actor.Attributes["container"][:12], err)
					return
				}
				if err := dd.updateContainerInfo(container); err != nil {
					log.Warningf("Error adding A/AAAA records for container %s: %s", container.ID[:12], err)
				}
			}
		}(msg)
	}

	return errors.New("docker event loop closed")
}

// getAnswer function takes a slice of net.IPs and returns a slice of A/AAAA RRs.
func getAnswer(zone string, ips []net.IP, ttl uint32, v6 bool) []dns.RR {
	answers := []dns.RR{}
	for _, ip := range ips {
		if !v6 {
			record := new(dns.A)
			record.Hdr = dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			}
			record.A = ip
			answers = append(answers, record)
		} else if v6 {
			record := new(dns.AAAA)
			record.Hdr = dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			}
			record.AAAA = ip
			answers = append(answers, record)
		}
	}
	return answers
}
