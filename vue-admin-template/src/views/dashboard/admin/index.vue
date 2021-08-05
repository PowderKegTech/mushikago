<template>
  <div class="dashboard-editor-container">
    <el-row style="background:#FFF;padding:150px 150px 0;margin-bottom:200px;">
     <start />
    </el-row>
  </div>
</template>

<script>
import Start from './components/Start'
export default {
  name: 'DashboardAdmin',
  components: {
    Start
  }
}
</script>

<style lang="scss" scoped>
.dashboard-editor-container {
  padding: 32px;
  background-color: rgb(240, 242, 245);
  position: relative;
  .chart-wrapper {
    background: #fff;
    padding: 16px 16px 0;
    margin-bottom: 32px;
  }
}
@media (max-width:1024px) {
  .chart-wrapper {
    padding: 8px;
  }
}
</style>

