package main

import (
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policyv1alpha1 "github.com/armadasystems/policy-management/api/v1alpha1"
	"github.com/armadasystems/policy-management/internal/controller"
	"github.com/armadasystems/policy-management/internal/enforce"
	"github.com/armadasystems/policy-management/internal/verify"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(policyv1alpha1.AddToScheme(scheme))
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: env("HEALTH_ADDR", ":8081"),
		LeaderElection:         env("LEADER_ELECT", "false") == "true",
		LeaderElectionID:       "policy-management.bridge.armada.ai",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	backend := &enforce.BridgeBackend{
		K8s:              mgr.GetClient(),
		LB:               enforce.NewHTTPOrchestratorLB(env("ORCHESTRATOR_URL", "http://bridge-orchestrator:8080")),
		Namespace:        env("MODEL_NAMESPACE", "armada-system"),
		GatewayNamespace: env("GATEWAY_NAMESPACE", "envoy-gateway-system"),
	}

	if err := (&controller.AccessPolicyReconciler{
		Client:          mgr.GetClient(),
		Backend:         backend,
		Prober:          verify.NewProber(env("PROBE_INSECURE_TLS", "true") == "true"),
		RequeueInterval: 2 * time.Minute,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AccessPolicy")
		os.Exit(1)
	}

	_ = mgr.AddHealthzCheck("healthz", healthz.Ping)
	_ = mgr.AddReadyzCheck("readyz", healthz.Ping)

	setupLog.Info("starting policy-management controller")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager exited")
		os.Exit(1)
	}
}
