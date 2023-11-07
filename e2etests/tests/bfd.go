// SPDX-License-Identifier:Apache-2.0

package tests

import (
	"fmt"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	frrk8sv1beta1 "github.com/metallb/frr-k8s/api/v1beta1"
	"github.com/metallb/frrk8stests/pkg/config"
	"github.com/metallb/frrk8stests/pkg/dump"
	"github.com/metallb/frrk8stests/pkg/infra"
	"github.com/metallb/frrk8stests/pkg/k8s"
	metallbfrr "go.universe.tf/e2etest/pkg/frr"
	frrconfig "go.universe.tf/e2etest/pkg/frr/config"
	"go.universe.tf/e2etest/pkg/frr/container"
	frrcontainer "go.universe.tf/e2etest/pkg/frr/container"
	"go.universe.tf/e2etest/pkg/ipfamily"
	metallbipfamily "go.universe.tf/e2etest/pkg/ipfamily"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

var _ = ginkgo.Describe("BFD", func() {
	var cs clientset.Interface
	var f *framework.Framework

	defer ginkgo.GinkgoRecover()
	clientconfig, err := framework.LoadConfig()
	framework.ExpectNoError(err)
	updater, err := config.NewUpdater(clientconfig)
	framework.ExpectNoError(err)
	reporter := dump.NewK8sReporter(framework.TestContext.KubeConfig, k8s.FRRK8sNamespace)

	f = framework.NewDefaultFramework("bgpfrr")
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	ginkgo.AfterEach(func() {
		if ginkgo.CurrentSpecReport().Failed() {
			testName := ginkgo.CurrentSpecReport().LeafNodeText
			dump.K8sInfo(testName, reporter)
			dump.BGPInfo(testName, infra.FRRContainers, f.ClientSet, f)
		}
	})

	ginkgo.BeforeEach(func() {
		ginkgo.By("Clearing any previous configuration")

		for _, c := range infra.FRRContainers {
			err := c.UpdateBGPConfigFile(frrconfig.Empty)
			framework.ExpectNoError(err)
		}
		err := updater.Clean()
		framework.ExpectNoError(err)

		cs = f.ClientSet
	})

	simpleProfile := frrk8sv1beta1.BFDProfile{
		Name: "simple",
	}
	fullProfile := frrk8sv1beta1.BFDProfile{
		Name:             "full1",
		ReceiveInterval:  60,
		TransmitInterval: 61,
		EchoInterval:     62,
		EchoMode:         false,
		PassiveMode:      false,
		MinimumTTL:       254,
	}
	withEchoMode := frrk8sv1beta1.BFDProfile{
		Name:             "echo",
		ReceiveInterval:  80,
		TransmitInterval: 81,
		EchoInterval:     82,
		EchoMode:         true,
		PassiveMode:      false,
		MinimumTTL:       254,
	}

	ginkgo.DescribeTable("should work with the given bfd profile", func(bfdProfileDefault frrk8sv1beta1.BFDProfile, bfdProfileRed frrk8sv1beta1.BFDProfile, pairingFamily ipfamily.Family) {

		ginkgo.By("pairing with nodes")
		for _, c := range infra.FRRContainers {
			err := container.PairWithNodes(cs, c, pairingFamily, func(container *frrcontainer.FRR) {
				container.NeighborConfig.BFDEnabled = true
			})
			framework.ExpectNoError(err)
		}

		withBFD := func(neigh *frrk8sv1beta1.Neighbor) {
			neigh.BFDProfile = bfdProfileDefault.Name
		}
		defaultVRFConfig, secrets := configForVRF(infra.DefaultVRFName, infra.FRRK8sASN, pairingFamily, withBFD)
		defaultVRFConfig.Spec.BGP.BFDProfiles = []frrk8sv1beta1.BFDProfile{bfdProfileDefault}
		err := updater.Update(secrets, defaultVRFConfig)
		framework.ExpectNoError(err)

		withBFDRed := func(neigh *frrk8sv1beta1.Neighbor) {
			neigh.BFDProfile = bfdProfileRed.Name
		}
		redVRFConfig, redSecrets := configForVRF(infra.VRFName, infra.FRRK8sASNVRF, pairingFamily, withBFDRed)
		redVRFConfig.Spec.BGP.BFDProfiles = []frrk8sv1beta1.BFDProfile{bfdProfileRed}
		err = updater.Update(redSecrets, redVRFConfig)
		framework.ExpectNoError(err)

		nodes, err := k8s.Nodes(cs)
		framework.ExpectNoError(err)

		for _, c := range infra.FRRContainers {
			ValidateFRRPeeredWithNodes(nodes, c, pairingFamily)
		}

		Eventually(func() error {
			for _, c := range infra.FRRContainers {
				bfdPeers, err := metallbfrr.BFDPeers(c.Executor)
				if err != nil {
					return err
				}
				err = metallbfrr.BFDPeersMatchNodes(nodes, bfdPeers, metallbipfamily.Family(pairingFamily), c.RouterConfig.VRF)
				if err != nil {
					return err
				}
				for _, peerConfig := range bfdPeers {
					profile := bfdProfileDefault
					if c.RouterConfig.VRF == infra.VRFName {
						profile = bfdProfileRed
					}
					toCompare := bfdProfileWithDefaults(profile, peerConfig.Multihop)
					ginkgo.By(fmt.Sprintf("Checking bfd parameters on %s", peerConfig.Peer))
					err := checkBFDConfigPropagated(toCompare, peerConfig)
					if err != nil {
						return err
					}
				}
			}
			return nil
		}, 2*time.Minute, 1*time.Second).ShouldNot(HaveOccurred())

	},
		ginkgo.Entry("IPV4 - default", simpleProfile, simpleProfile, ipfamily.IPv4),
		ginkgo.Entry("IPV4 - full params", fullProfile, fullProfile, ipfamily.IPv4),
		ginkgo.Entry("IPV4 - echo mode enabled", withEchoMode, fullProfile, ipfamily.IPv4), // echo mode doesn't work with VRF
		ginkgo.Entry("IPV6 - default", simpleProfile, simpleProfile, ipfamily.IPv6),
		ginkgo.Entry("IPV6 - full params", fullProfile, fullProfile, ipfamily.IPv6),
		ginkgo.Entry("IPV6 - echo mode enabled", withEchoMode, fullProfile, ipfamily.IPv6), // echo mode doesn't work with VRF
	)
})

func configForVRF(vrfName string, asn uint32, pairingFamily ipfamily.Family, modifyNeighbors ...func(neighs *frrk8sv1beta1.Neighbor)) (frrk8sv1beta1.FRRConfiguration, []corev1.Secret) {
	frrs := config.ContainersForVRF(infra.FRRContainers, vrfName)
	peersConfig := config.PeersForContainers(frrs, pairingFamily)
	neighbors := config.NeighborsFromPeers(peersConfig.PeersV4, peersConfig.PeersV6)

	for i := range neighbors {
		for _, modify := range modifyNeighbors {
			modify(&neighbors[i])
		}
	}

	config := frrk8sv1beta1.FRRConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testvrf" + vrfName,
			Namespace: k8s.FRRK8sNamespace,
		},
		Spec: frrk8sv1beta1.FRRConfigurationSpec{
			BGP: frrk8sv1beta1.BGPConfig{
				Routers: []frrk8sv1beta1.Router{
					{
						ASN:       asn,
						VRF:       vrfName,
						Neighbors: neighbors,
					},
				},
			},
		},
	}
	return config, peersConfig.Secrets
}

func bfdProfileWithDefaults(profile frrk8sv1beta1.BFDProfile, multiHop bool) frrk8sv1beta1.BFDProfile {
	res := frrk8sv1beta1.BFDProfile{}
	res.Name = profile.Name
	res.ReceiveInterval = valueWithDefault(profile.ReceiveInterval, 300)
	res.TransmitInterval = valueWithDefault(profile.TransmitInterval, 300)
	res.DetectMultiplier = valueWithDefault(profile.DetectMultiplier, 3)
	res.EchoInterval = valueWithDefault(profile.EchoInterval, 50)
	res.MinimumTTL = valueWithDefault(profile.MinimumTTL, 254)
	res.EchoMode = profile.EchoMode
	res.PassiveMode = profile.PassiveMode

	if multiHop {
		res.EchoMode = false
		res.EchoInterval = 50
	}

	return res
}

func valueWithDefault(v uint32, def uint32) uint32 {
	if v != 0 {
		return v
	}
	return def
}
