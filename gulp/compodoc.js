const gulp = require('gulp');
const compodoc= require('@compodoc/gulp-compodoc');

gulp.task('compodoc', () => {
  return gulp.src(['src/**/*.ts', '!src/**/*.spec.ts'])
    .pipe(compodoc({
      output: 'documentation',
      tsconfig: 'src/tsconfig.json',
      serve: false
    }));
});

gulp.task('compodoc:serve', () => {
  return gulp.src(['src/**/*.ts', '!src/**/*.spec.ts'])
    .pipe(compodoc({
      output: 'documentation',
      tsconfig: 'src/tsconfig.json',
      serve: true,
      port: 5550
    }));
});
