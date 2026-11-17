# One held-out analysis session (decisions 2026-11-11, docs/plans/heldout-aws-plan.md).
# Every compared system (MicroTRACE, SAGE, KAIROS, ORTHRUS) runs on the one analysis host,
# an m7i.8xlarge (32 vCPU, 128 GB, no GPU, PTP hardware clock), one system at a time with
# 8 worker processes. Optional side nodes: Exp. 3 sender nodes and the Exp. 5 kind node,
# never the analysis host itself. Data and results live in the permanent storage stack
# (../storage), which this stack never creates or destroys.
#
#   terraform init && terraform plan -var bucket=<storage bucket>
#   terraform apply ...             # only after the session price is agreed
#   terraform destroy               # same session
#
# Cost cap: every machine shuts down (and terminates) after var.max_hours.
# Truth: the analysis host gets the storage stack's analysis profile (no truth reads);
# only a scoring session (-var scoring=true) gets the scoring profile.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = var.aws_profile
  default_tags {
    tags = {
      Project = "MicroTRACE"
      Purpose = "heldout-session"
      Session = var.session
    }
  }
}

# --- Network (as experiments/aws/pidsmaker) ----------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = "10.78.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "mt-heldout" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "mt-heldout" }
}

# Public subnet for outbound traffic only (packages, S3); no inbound from the internet.
resource "aws_subnet" "this" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.78.1.0/24"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
  tags                    = { Name = "mt-heldout" }
}

resource "aws_route_table" "this" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "mt-heldout" }
}

resource "aws_route_table_association" "this" {
  subnet_id      = aws_subnet.this.id
  route_table_id = aws_route_table.this.id
}

# S3 traffic stays on the AWS network and costs nothing (gateway endpoint).
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.this.id]
}

resource "aws_security_group" "eice" {
  name   = "mt-heldout-eice-${var.session}"
  vpc_id = aws_vpc.this.id
}

resource "aws_security_group" "node" {
  name   = "mt-heldout-node-${var.session}"
  vpc_id = aws_vpc.this.id
}

resource "aws_vpc_security_group_egress_rule" "eice_to_node" {
  security_group_id            = aws_security_group.eice.id
  referenced_security_group_id = aws_security_group.node.id
  ip_protocol                  = "tcp"
  from_port                    = 22
  to_port                      = 22
}

resource "aws_vpc_security_group_ingress_rule" "node_from_eice" {
  security_group_id            = aws_security_group.node.id
  referenced_security_group_id = aws_security_group.eice.id
  ip_protocol                  = "tcp"
  from_port                    = 22
  to_port                      = 22
}

# Sender nodes -> analysis host (Exp. 3 transport) and GRE -> kind node (Exp. 5).
resource "aws_vpc_security_group_ingress_rule" "node_from_node" {
  security_group_id            = aws_security_group.node.id
  referenced_security_group_id = aws_security_group.node.id
  ip_protocol                  = "-1"
}

resource "aws_vpc_security_group_egress_rule" "node_out" {
  security_group_id = aws_security_group.node.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_ec2_instance_connect_endpoint" "this" {
  subnet_id          = aws_subnet.this.id
  security_group_ids = [aws_security_group.eice.id]
  preserve_client_ip = false
  tags               = { Name = "mt-heldout" }
}

# Same rack for the analysis host and the side nodes: short, stable network paths. Every
# node of a session is created in the same apply (a cluster group refuses late joiners
# more often); set placement = false if AWS reports InsufficientInstanceCapacity.
resource "aws_placement_group" "this" {
  count    = var.placement ? 1 : 0
  name     = "mt-heldout-${var.session}"
  strategy = "cluster"
}

locals {
  placement = var.placement ? aws_placement_group.this[0].id : null
  # First boot only (cloud-init runs user data once), then one reboot:
  # - cost cap: an absolute deadline in /etc/mt-deadline (never moved once written),
  #   re-armed by mt-boot.service on every boot; a missing or unreadable deadline shuts
  #   the machine down at once;
  # - system packages the runners need (docker + compose, AWS CLI v2, chrony, time,
  #   build tools for SAGE/FlexFringe and DKMS);
  # - the ENA PTP hardware clock: AWS's own ENA driver (amzn-drivers, DKMS) with
  #   phc_enable=1, because the in-kernel driver of this Ubuntu kernel has no such option.
  #   On every boot chrony gets the PHC refclock only if /dev/ptp0 exists and is the ENA
  #   clock; else it keeps Amazon Time Sync over NTP. /var/log/mt-clock.txt records
  #   `chronyc tracking`, not an assumption.
  user_data_base = <<-EOT
    #!/bin/bash
    set -u
    exec > /var/log/mt-system.log 2>&1
    [ -s /etc/mt-deadline ] || echo $(( $(date +%s) + ${var.max_hours} * 3600 )) > /etc/mt-deadline
    cat > /usr/local/sbin/mt-boot.sh <<'SH'
    #!/bin/bash
    d=$(cat /etc/mt-deadline 2>/dev/null); now=$(date +%s)
    case "$d" in ''|*[!0-9]*) /sbin/shutdown -h now; exit 0;; esac
    if [ "$now" -ge "$d" ]; then /sbin/shutdown -h now; exit 0; fi
    systemd-run --unit=mt-cost-cap --on-active=$(( d - now ))s /sbin/shutdown -h now
    clk=""
    [ -e /sys/class/ptp/ptp0/clock_name ] && clk=$(cat /sys/class/ptp/ptp0/clock_name)
    if echo "$clk" | grep -qi ena; then
      echo "refclock PHC /dev/ptp0 poll 0 delay 0.000010 prefer" > /etc/chrony/conf.d/ena-phc.conf
    else
      rm -f /etc/chrony/conf.d/ena-phc.conf
    fi
    systemctl restart chrony
    sleep 20
    echo "$(date -u +%FT%TZ) ptp0='$clk' $(chronyc -n tracking | grep -E 'Reference ID|System time' | xargs)" >> /var/log/mt-clock.txt
    SH
    chmod 755 /usr/local/sbin/mt-boot.sh
    cat > /etc/systemd/system/mt-boot.service <<'UNIT'
    [Unit]
    Description=MicroTRACE cost cap and clock source
    After=network-online.target chrony.service
    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/mt-boot.sh
    [Install]
    WantedBy=multi-user.target
    UNIT
    systemctl daemon-reload && systemctl enable mt-boot.service
    systemd-run --unit=mt-cost-cap-first --on-active=${var.max_hours}h /sbin/shutdown -h now
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q docker.io docker-compose-v2 chrony time git make g++ cmake unzip curl dkms \
      "linux-headers-$(uname -r)"
    usermod -aG docker ubuntu
    curl -sSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscli.zip
    unzip -q /tmp/awscli.zip -d /tmp && /tmp/aws/install --update
    tag=$(git ls-remote --tags https://github.com/amzn/amzn-drivers.git 'ena_linux_*' | sed 's#.*refs/tags/##' \
          | grep -v '\^{}' | sort -V | tail -1)
    git clone -q --depth 1 --branch "$tag" https://github.com/amzn/amzn-drivers.git /usr/src/amzn-drivers-src
    v=$${tag#ena_linux_}
    mkdir -p "/usr/src/amzn-drivers-$v" && cp -r /usr/src/amzn-drivers-src/* "/usr/src/amzn-drivers-$v/"
    cat > "/usr/src/amzn-drivers-$v/dkms.conf" <<DK
    PACKAGE_NAME="ena"
    PACKAGE_VERSION="$v"
    CLEAN="make -C kernel/linux/ena clean"
    MAKE="ENA_PHC_INCLUDE=1 BUILD_KERNEL=\$${kernelver} make -C kernel/linux/ena"
    BUILT_MODULE_NAME[0]="ena"
    BUILT_MODULE_LOCATION="kernel/linux/ena"
    DEST_MODULE_LOCATION[0]="/updates"
    DEST_MODULE_NAME[0]="ena"
    AUTOINSTALL="yes"
    DK
    if dkms add -m amzn-drivers -v "$v" && dkms build -m amzn-drivers -v "$v" && dkms install -m amzn-drivers -v "$v"; then
      echo "options ena phc_enable=1" > /etc/modprobe.d/ena-phc.conf
      echo "ENA driver $tag installed" >> /var/log/mt-clock.txt
    else
      echo "ENA driver $tag FAILED to build; NTP only" >> /var/log/mt-clock.txt
    fi
    update-initramfs -u
    touch /var/lib/mt-system-ready
    /sbin/reboot
  EOT

  # Unattended job (var.autorun, analysis host only; docs/plans/ml-model-compare-plan.md):
  # mt-job.service starts on the boot after setup, as ubuntu, gets the code bundle and runs
  # var.job_script, which syncs its results to s3://<job_bucket>/results/<session>/ and shuts
  # the machine down. If the job ends without doing so, the wrapper copies its log up and
  # shuts down itself; the cost cap above still ends the machine in every case. With
  # autorun false the analysis host's user data is exactly user_data_base.
  job_setup = <<-EOT
    cat > /etc/mt-job.env <<'ENV'
    BUCKET=${var.job_bucket}
    COMMIT=${var.job_commit}
    SESSION=${var.session}
    JOB=${var.job_script}
    ENV
    cat > /usr/local/sbin/mt-job.sh <<'SH'
    #!/bin/bash
    . /etc/mt-job.env
    [ -f /var/lib/mt-job-done ] && exit 0
    log=/var/log/mt-job.log
    echo "$(date -u +%FT%TZ) mt-job start $SESSION $COMMIT $JOB" >> $log
    su - ubuntu -c "cd ~ && { [ -d code/.git ] || { aws s3 cp --only-show-errors s3://$BUCKET/code/$COMMIT.bundle /tmp/code.bundle && git clone -q /tmp/code.bundle code; }; } && git -C code checkout -q $COMMIT && BUCKET=$BUCKET COMMIT=$COMMIT SESSION=$SESSION bash code/$JOB" >> $log 2>&1
    rc=$?
    touch /var/lib/mt-job-done
    echo "$(date -u +%FT%TZ) mt-job exit $rc" >> $log
    aws s3 cp --only-show-errors $log s3://$BUCKET/results/$SESSION/logs/mt-job.log
    /sbin/shutdown -h now
    SH
    chmod 755 /usr/local/sbin/mt-job.sh
    cat > /etc/systemd/system/mt-job.service <<'UNIT'
    [Unit]
    Description=MicroTRACE unattended session job
    Wants=network-online.target
    After=network-online.target mt-boot.service
    ConditionPathExists=/var/lib/mt-system-ready
    ConditionPathExists=!/var/lib/mt-job-done
    [Service]
    Type=oneshot
    TimeoutStartSec=infinity
    ExecStart=/usr/local/sbin/mt-job.sh
    [Install]
    WantedBy=multi-user.target
    UNIT
    systemctl daemon-reload && systemctl enable mt-job.service
  EOT

  user_data_analysis = var.autorun ? replace(local.user_data_base, "touch /var/lib/mt-system-ready\n",
  "${local.job_setup}touch /var/lib/mt-system-ready\n") : local.user_data_base
}

# --- Analysis host -------------------------------------------------------------------

resource "aws_instance" "analysis" {
  dynamic "instance_market_options" {
    for_each = var.spot ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        instance_interruption_behavior = "terminate"
        spot_instance_type             = "one-time"
      }
    }
  }
  ami                                  = var.ami_id
  instance_type                        = var.analysis_type
  subnet_id                            = aws_subnet.this.id
  vpc_security_group_ids               = [aws_security_group.node.id]
  placement_group                      = local.placement
  iam_instance_profile                 = var.scoring ? var.scoring_profile : var.analysis_profile
  instance_initiated_shutdown_behavior = var.spot ? null : "terminate" # one-time Spot already terminates; AWS refuses the attribute on Spot
  ebs_optimized                        = true

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.disk_gb
    throughput            = 500
    iops                  = 6000
    delete_on_termination = true
    encrypted             = true
    tags                  = { Project = "MicroTRACE", Session = var.session }
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2 # containers may need instance credentials
  }

  user_data = local.user_data_analysis
  tags      = { Name = "mt-heldout-analysis", Role = var.scoring ? "scoring" : "analysis" }

  lifecycle {
    precondition {
      condition     = !var.autorun || (var.job_bucket != "" && length(var.job_commit) == 40)
      error_message = "autorun needs job_bucket and the full 40-character job_commit."
    }
  }
}

# --- Side nodes (never the analysis host) ------------------------------------------------

resource "aws_instance" "sender" {
  dynamic "instance_market_options" {
    for_each = var.spot ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        instance_interruption_behavior = "terminate"
        spot_instance_type             = "one-time"
      }
    }
  }
  count                                = var.senders
  ami                                  = var.ami_id
  instance_type                        = var.sender_type
  subnet_id                            = aws_subnet.this.id
  vpc_security_group_ids               = [aws_security_group.node.id]
  placement_group                      = local.placement
  iam_instance_profile                 = var.analysis_profile
  instance_initiated_shutdown_behavior = var.spot ? null : "terminate" # one-time Spot already terminates; AWS refuses the attribute on Spot

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 200
    delete_on_termination = true
    encrypted             = true
    tags                  = { Project = "MicroTRACE", Session = var.session }
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data = local.user_data_base
  tags      = { Name = "mt-heldout-sender-${count.index}", Role = "sender" }
}

resource "aws_instance" "kind" {
  dynamic "instance_market_options" {
    for_each = var.spot ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        instance_interruption_behavior = "terminate"
        spot_instance_type             = "one-time"
      }
    }
  }
  count                                = var.kind_node ? 1 : 0
  ami                                  = var.ami_id
  instance_type                        = var.kind_type
  iam_instance_profile                 = var.analysis_profile # code bundle in, results/ out (Exp. 5 part B); never truth
  subnet_id                            = aws_subnet.this.id
  vpc_security_group_ids               = [aws_security_group.node.id]
  placement_group                      = local.placement
  instance_initiated_shutdown_behavior = var.spot ? null : "terminate" # one-time Spot already terminates; AWS refuses the attribute on Spot

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 80
    delete_on_termination = true
    encrypted             = true
    tags                  = { Project = "MicroTRACE", Session = var.session }
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data = local.user_data_base
  tags      = { Name = "mt-heldout-kind", Role = "kind" }
}
