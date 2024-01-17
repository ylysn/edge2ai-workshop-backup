#!/usr/bin/env bash

# Mandatory component:              BASE
# Common components to CDH and CDP: CDSW, FLINK, HBASE HDFS, HIVE, HUE, IMPALA, KAFKA, KUDU,
#                                   NIFI, OOZIE, SCHEMAREGISTRY, SMM, SRM, SOLR, SPARK_ON_YARN, YARN,
#                                   ZOOKEEPER
# CDP-only components:              ATLAS, KNOX, LIVY, OZONE, RANGER, ZEPPELIN
# ECS required components:          HIVE, RANGER, ATLAS, HDFS, OZONE
CM_SERVICES=BASE,ZOOKEEPER,HDFS,YARN,HIVE,HUE,IMPALA,KAFKA,KUDU,NIFI,OOZIE,OZONE,SCHEMAREGISTRY,SPARK_ON_YARN,SMM,KNOX,FLINK,SOLR,HBASE,ATLAS,RANGER,LIVY,ZEPPELIN,ECS
ENABLE_KERBEROS=yes
ENABLE_TLS=yes
KERBEROS_TYPE=IPA
##### Add repo credentials
REMOTE_REPO_USR=
REMOTE_REPO_PWD=

#####  Java Package
JAVA_PACKAGE_NAME=java-11-openjdk-devel

##### Maven binary
MAVEN_BINARY_URL=https://downloads.apache.org/maven/maven-3/3.9.4/binaries/apache-maven-3.9.4-bin.tar.gz

BASE_URI=

#####  CM
CM_VERSION=7.11.3.3
_CM_BUILD_PATH=patch/${CM_VERSION}-47960007
CM_MAJOR_VERSION=${CM_VERSION%%.*}
CM_REPO_AS_TARBALL_URL=https://archive.cloudera.com/p/cm${CM_MAJOR_VERSION}/${_CM_BUILD_PATH}/repo-as-tarball/cm${CM_VERSION}-redhat7.tar.gz
CM_BASE_URL=
CM_REPO_FILE_URL=

#####  CDH
CDH_VERSION=7.1.9
CDH_BUILD=${CDH_VERSION}-1.cdh${CDH_VERSION}.p0.44702451
_CDH_BUILD_PATH=${CDH_VERSION}
CDH_MAJOR_VERSION=${CDH_VERSION%%.*}
CDH_PARCEL_REPO=https://archive.cloudera.com/p/cdh${CDH_MAJOR_VERSION}/${_CDH_BUILD_PATH}/parcels/

#####  CFM
CFM_VERSION=2.1.6.1001
CFM_BUILD=${CFM_VERSION}-2
CFM_MAJOR_VERSION=${CFM_VERSION%%.*}
NIFI_VERSION=1.23.1
NIFI_REGISTRY_VERSION=${NIFI_VERSION}
CFM_PARCEL_REPO=https://archive.cloudera.com/p/cfm${CFM_MAJOR_VERSION}/${CFM_VERSION}/redhat7/yum/tars/parcel/
CFM_NIFI_CSD_URL=https://archive.cloudera.com/p/cfm${CFM_MAJOR_VERSION}/${CFM_VERSION}/redhat7/yum/tars/parcel/NIFI-${NIFI_VERSION}.${CFM_BUILD}.jar
CFM_NIFIREG_CSD_URL=https://archive.cloudera.com/p/cfm${CFM_MAJOR_VERSION}/${CFM_VERSION}/redhat7/yum/tars/parcel/NIFIREGISTRY-${NIFI_REGISTRY_VERSION}.${CFM_BUILD}.jar

#####  CDSW
# If version is set, install will be attempted
CDSW_VERSION=1.10.5
CDSW_BUILD=1.10.5.p1.47677668
CDSW_PARCEL_REPO=https://archive.cloudera.com/p/cdsw1/${CDSW_VERSION}/parcels/
CDSW_CSD_URL=https://archive.cloudera.com/p/cdsw1/${CDSW_VERSION}/csd/CLOUDERA_DATA_SCIENCE_WORKBENCH-CDPDC-${CDSW_VERSION}.jar

#####  CEM
CEM_VERSION=2.0.0.0
CEM_BUILD=${CEM_VERSION}-53
CEM_MAJOR_VERSION=${CEM_VERSION%%.*}
EFM_TARBALL_URL=https://archive.cloudera.com/p/CEM/ubuntu20/1.x/updates/${CEM_VERSION}/tars/efm/efm-${CEM_BUILD}-bin.tar.gz

#####  CEM AGENTS
MINIFI_VERSION=1.23.09
MINIFI_BUILD=${MINIFI_VERSION}-b50
MINIFI_TARBALL_URL=https://archive.cloudera.com/p/cem-agents/${MINIFI_VERSION}/ubuntu22/apt/tars/nifi-minifi-cpp/nifi-minifi-cpp-${MINIFI_BUILD}-bin-centos.tar.gz
MINIFITK_TARBALL_URL=https://archive.cloudera.com/p/cem-agents/${MINIFI_VERSION}/ubuntu22/apt/tars/nifi-minifi-cpp/nifi-minifi-cpp-${MINIFI_BUILD}-extra-extensions-centos.tar.gz

#####   CSA
CSA_VERSION=1.11.0.1
FLINK_VERSION=1.16.2
FLINK_BUILD=${FLINK_VERSION}-csa${CSA_VERSION}-cdh7.1.9.0-387-45580652
CSA_PARCEL_REPO=https://archive.cloudera.com/p/csa/${CSA_VERSION}/parcels/
FLINK_CSD_URL=https://archive.cloudera.com/p/csa/${CSA_VERSION}/csd/FLINK-${FLINK_BUILD}.jar
SSB_CSD_URL=https://archive.cloudera.com/p/csa/${CSA_VERSION}/csd/SQL_STREAM_BUILDER-${FLINK_BUILD}.jar

#####   ECS
ECS_VERSION=1.5.2
ECS_RELEASE=${ECS_VERSION}-h1-b1
ECS_GBN=47204890
ECS_BUILD=${ECS_RELEASE}-ecs-${ECS_RELEASE}.p0.${ECS_GBN}
ECS_REPO=https://archive.cloudera.com/p/cdp-pvc-ds/1.5.2-h1/
ECS_PARCEL_REPO=${ECS_REPO}parcels/

#####   SPARK3
SPARK3_VERSION=3.3.7190.3
SPARK3_BUILD=3.3.2.${SPARK3_VERSION}-1-1
SPARK3_GBN=48047943
SPARK3_BUILD=${SPARK3_BUILD}.p0.${SPARK3_GBN}
SPARK3_REPO=https://archive.cloudera.com/p/spark3/${SPARK3_VERSION}/
SPARK3_PARCEL_REPO=${SPARK3_REPO}parcels/


# Parcels to be pre-downloaded during install.
# Cloudera Manager will download any parcels that are not already downloaded previously.
CDP_PARCEL_URLS=(
  hadoop         "$CDH_BUILD"                         "$CDH_PARCEL_REPO"
  nifi           "$CFM_BUILD"                         "$CFM_PARCEL_REPO"
  flink          "$FLINK_BUILD"                       "$CSA_PARCEL_REPO"
  cdp-pvc        "$ECS_BUILD"                         "$ECS_PARCEL_REPO"
  spark3         "$SPARK3_BUILD"                      "$SPARK3_PARCEL_REPO"
)

CDP_CSD_URLS=(
  $CFM_NIFI_CSD_URL
  $CFM_NIFIREG_CSD_URL
  $FLINK_CSD_URL
  $SSB_CSD_URL
)
