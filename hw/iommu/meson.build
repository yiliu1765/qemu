iommu_ss = ss.source_set()
iommu_ss.add(files(
  'iommu.c',
))

specific_ss.add_all(when: 'CONFIG_IOMMU', if_true: iommu_ss)
